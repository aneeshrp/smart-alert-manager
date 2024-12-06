from flask import Flask, request, jsonify
import requests
import redis
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import json
import time

app = Flask(__name__)

# Slack configuration
slack_webhook_url = "https://hooks.slack.com/services/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"

# Redis configuration
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

# Rule-based filtering rules
RULES = {
    "HighCPUUsage": "critical"
}

CORRELATION_RULES = {
    "HighCPUUsage": ["HighMemoryUsage", "HighNetworkTraffic"]
}

# Redis key expiry time for historical data (in seconds)
HISTORICAL_ALERT_EXPIRY = 3600  # 1 hour

def send_to_slack(alert):
    try:
        alert_name = alert['labels'].get('alertname', 'Unknown Alert')
        severity = alert['labels'].get('severity', 'unknown')
        description = alert['annotations'].get('description', 'No description provided')

        message = {
            "text": f"Alert: {alert_name}\nSeverity: {severity}\nDescription: {description}"
        }

        response = requests.post(slack_webhook_url, json=message)

        if response.status_code != 200:
            print(f"Error sending to Slack: {response.status_code} - {response.text}")
        return response
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def is_repeated_alert(alert):
    alert_key = f"{alert['alertname']}:{alert['instance']}"
    if redis_client.exists(alert_key):
        print(f"Alert {alert_key} is a repeated alert.")
        return True
    else:
        redis_client.set(alert_key, json.dumps(alert), ex=HISTORICAL_ALERT_EXPIRY)
        return False

@app.route('/api/v2/alerts', methods=['POST'])
def receive_alert():
    try:
        alert_list = request.json  # Process the list of alerts
        
        # Loop through the list of alerts and process each one
        for alert in alert_list:
            alert_name = alert['labels'].get('alertname', 'Unknown Alert')
            severity = alert['labels'].get('severity', 'unknown')
            
            # Apply rule-based filtering: only process alerts with matching severity
            if severity == RULES.get(alert_name, 'critical'):
                # Apply historical filtering
                if not is_repeated_alert(alert['labels']):
                    send_to_slack(alert)
                else:
                    print(f"Alert {alert_name} suppressed by historical filter.")
            else:
                print(f"Alert {alert_name} with severity {severity} suppressed by rule-based filter.")
        
        return jsonify({"message": "Alerts processed and sent to Slack"}), 200
    except Exception as e:
        print(f"Error processing alert: {e}")
        return jsonify({"message": "Failed to process alert"}), 500
        
def get_adaptive_threshold(alert_name):
    # Retrieve historical data
    historical_data = redis_client.lrange(f"{alert_name}:metrics", 0, -1)
    if not historical_data:
        return 80  # Default threshold if no historical data is available
    
    # Convert data to numeric values
    historical_values = [float(value) for value in historical_data]
    
    # Calculate an adaptive threshold (e.g., mean + 1 standard deviation)
    mean = sum(historical_values) / len(historical_values)
    stddev = (sum((x - mean) ** 2 for x in historical_values) / len(historical_values)) ** 0.5
    adaptive_threshold = mean + stddev
    
    return adaptive_threshold

def is_above_adaptive_threshold(alert):
    alert_value = float(alert['annotations'].get('value', '0'))
    alert_name = alert['labels'].get('alertname', 'Unknown Alert')
    
    adaptive_threshold = get_adaptive_threshold(alert_name)
    return alert_value > adaptive_threshold

def is_correlated_alert(alert):
    alert_name = alert['labels'].get('alertname', 'Unknown Alert')
    correlated_alerts = CORRELATION_RULES.get(alert_name, [])
    
    for correlated_alert in correlated_alerts:
        if redis_client.exists(f"{correlated_alert}:{alert['labels'].get('instance')}"):
            return True
    return False

def handle_correlated_alert(alert):
    if is_correlated_alert(alert):
        # Handle correlated alert (e.g., aggregate into a single message)
        print(f"Alert {alert['labels'].get('alertname')} correlated with another alert.")
        return True
    return False

def store_alert_for_trend_analysis(alert):
    alert_name = alert['labels'].get('alertname', 'Unknown Alert')
    timestamp = time.time()
    alert_data = {
        "timestamp": timestamp,
        "value": alert['annotations'].get('value', '0')
    }
    redis_client.rpush(f"{alert_name}:trends", json.dumps(alert_data))

def auto_scale_threshold(alert_name):
    historical_data = [float(value) for value in redis_client.lrange(f"{alert_name}:metrics", 0, -1)]
    
    if not historical_data:
        return None
    
    mean_usage = sum(historical_data) / len(historical_data)
    stddev_usage = (sum((x - mean_usage) ** 2 for x in historical_data) / len(historical_data)) ** 0.5
    
    # Scale the threshold up by one standard deviation if the mean usage is consistently high
    scaled_threshold = mean_usage + stddev_usage
    
    # Store the new threshold in Redis
    redis_client.set(f"{alert_name}:scaled_threshold", scaled_threshold)
    return scaled_threshold        

def test_redis_connection():
    try:
        # Attempt to set a key in Redis
        test_key = "test_key"
        test_value = "test_value"
        redis_client.set(test_key, test_value)
        
        # Attempt to retrieve the key from Redis
        retrieved_value = redis_client.get(test_key)
        
        if retrieved_value == test_value:
            print("Redis connectivity test successful!")
            return True
        else:
            print("Redis connectivity test failed: Value mismatch.")
            return False
    except Exception as e:
        print(f"Redis connectivity test failed: {e}")
        return False


# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=6000)

if __name__ == '__main__':
    if test_redis_connection():
        print("Starting Flask application...")
        app.run(host='0.0.0.0', port=6000)
    else:
        print("Flask application will not start due to Redis connectivity issues.")

