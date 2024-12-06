from flask import Flask, request, jsonify
from prometheus_client import Gauge, start_http_server
import requests
import redis
import json
import datetime
import time

app = Flask(__name__)

# Load configuration from JSON file
def load_config():
    with open('config.json', 'r') as config_file:
        return json.load(config_file)

# Save configuration to JSON file
def save_config(config):
    with open('config.json', 'w') as config_file:
        json.dump(config, config_file, indent=4)

# Use the loaded config for rules, correlation rules, and time-based rules
config = load_config()
RULES = config['rules']
CORRELATION_RULES = config['correlation_rules']
TIME_BASED_RULES = config.get('time_based_rules', {})

# Slack configuration
slack_webhook_url = "https://hooks.slack.com/services/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"

# Redis configuration
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

# Redis key expiry time for historical data (in seconds)
HISTORICAL_ALERT_EXPIRY = 3600  # 1 hour

# Create Gauges for each severity level
total_critical_alerts = Gauge('total_critical_alerts', 'Total number of critical alerts generated')
filtered_critical_alerts = Gauge('filtered_critical_alerts', 'Number of critical alerts generated after applying filters')
critical_alert_reduction = Gauge('critical_alert_reduction_percentage', 'Percentage reduction in critical alerts after filtering')

total_warning_alerts = Gauge('total_warning_alerts', 'Total number of warning alerts generated')
filtered_warning_alerts = Gauge('filtered_warning_alerts', 'Number of warning alerts generated after applying filters')
warning_alert_reduction = Gauge('warning_alert_reduction_percentage', 'Percentage reduction in warning alerts after filtering')


def evaluate_condition(condition, alert_value):
    try:
        # Replace placeholder 'value' with the actual alert value
        condition = condition.replace("value", str(alert_value))
        # Evaluate the condition as a Python expression
        return eval(condition)
    except Exception as e:
        print(f"Error evaluating condition: {e}")
        return False

def process_alert(alert):
    rule_name = alert['labels'].get('alertname')
    config = load_config()

    # Get time-based rules if they exist
    time_based_rule = config['time_based_rules'].get(rule_name)
    if time_based_rule:
        current_time = datetime.now().time()
        peak_start = datetime.strptime(time_based_rule['peak_hours']['start'], '%H:%M').time()
        peak_end = datetime.strptime(time_based_rule['peak_hours']['end'], '%H:%M').time()

        off_start = datetime.strptime(time_based_rule['off_hours']['start'], '%H:%M').time()
        off_end = datetime.strptime(time_based_rule['off_hours']['end'], '%H:%M').time()

        # Apply peak hours threshold
        if peak_start <= current_time <= peak_end:
            threshold = float(time_based_rule['peak_hours']['threshold'])
        else:
            threshold = float(time_based_rule['off_hours']['threshold'])

        # Compare alert value against time-based threshold
        alert_value = float(alert['annotations'].get('value', '0'))
        if alert_value < threshold:
            print(f"Alert {rule_name} suppressed by time-based rule.")
            return

    # Determine the severity of the alert
    alert_severity = alert['labels'].get('severity', 'unknown')
    alert_value = float(alert['annotations'].get('value', '0'))

    # Get the condition from the rule
    rule_condition = config['rules'][rule_name]['condition']

    if alert_severity == 'critical':
        # Process critical alerts
        print(f"Processing critical alert: {rule_name} with value {alert_value}")

        # Evaluate the condition using the actual alert value
        if evaluate_condition(rule_condition, alert_value):
            send_to_slack(alert)
        else:
            print(f"Critical alert {rule_name} suppressed by condition check.")

        # Update Prometheus metrics
        total_critical_alerts.inc()
        filtered_critical_alerts.inc()

    elif alert_severity == 'warning':
        # Process warning alerts
        print(f"Processing warning alert: {rule_name} with value {alert_value}")

        # Evaluate the condition using the actual alert value
        if evaluate_condition(rule_condition, alert_value):
            send_to_slack(alert)
        else:
            print(f"Warning alert {rule_name} suppressed by condition check.")

        # Update Prometheus metrics
        total_warning_alerts.inc()
        filtered_warning_alerts.inc()

    else:
        # Handle any other alert severities if necessary
        print(f"Unhandled alert severity: {alert_severity} for alert {rule_name}.")


    # Existing processing logic
    alert_severity = alert.get('severity', 'unknown')
    if alert_severity == 'critical':
        # Process critical alerts
        pass
    elif alert_severity == 'warning':
        # Process warning alerts
        pass


    elif alert_severity == 'warning':
        # Update the warning alert metrics
        total_warning_alert_count = len(warning_alerts_before_filtering)
        filtered_warning_alert_count = len(warning_alerts_after_filtering)

        total_warning_alerts.set(total_warning_alert_count)
        filtered_warning_alerts.set(filtered_warning_alert_count)
        warning_reduction_percentage = ((total_warning_alert_count - filtered_warning_alert_count) / total_warning_alert_count) * 100
        warning_alert_reduction.set(warning_reduction_percentage)

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

def get_adaptive_threshold(alert_name):
    historical_data = redis_client.lrange(f"{alert_name}:metrics", 0, -1)
    
    if not historical_data:
        return 80  # Default threshold if no historical data is available
    
    historical_values = [float(value) for value in historical_data]
    
    # Adjusting the calculation to be more lenient
    mean = sum(historical_values) / len(historical_values)
    stddev = (sum((x - mean) ** 2 for x in historical_values) / len(historical_values)) ** 0.5
    adaptive_threshold = mean + (stddev * 0.5)  # Multiplying stddev by 0.5 to make it more lenient
    
    print(f"Calculated adaptive threshold for {alert_name}: {adaptive_threshold} based on historical data: {historical_values}")
    return adaptive_threshold




def get_time_of_day():
    current_hour = datetime.datetime.now().hour
    return 'peak_hours' if 9 <= current_hour < 18 else 'off_hours'

def get_time_based_threshold(alert_name):
    time_of_day = get_time_of_day()
    return TIME_BASED_RULES.get(alert_name, {}).get(time_of_day, 80)

def is_above_adaptive_threshold(alert):
    alert_value = float(alert['annotations'].get('value', '0'))
    alert_name = alert['labels'].get('alertname', 'Unknown Alert')
    adaptive_threshold = get_adaptive_threshold(alert_name)
    #print(f"Alert {alert_name} with value {alert_value} is being compared against adaptive threshold {adaptive_threshold}.")
    return alert_value > adaptive_threshold

def store_metric_for_analysis(alert):
    alert_name = alert['labels'].get('alertname', 'Unknown Alert')
    alert_value = alert['annotations'].get('value', None)
    
    if alert_value is not None:
        redis_client.rpush(f"{alert_name}:metrics", alert_value)
        redis_client.expire(f"{alert_name}:metrics", HISTORICAL_ALERT_EXPIRY)
        #print(f"Stored {alert_value} for {alert_name} in Redis.")
    else:
        print(f"Alert {alert_name} does not have a valid 'value'.")


def is_correlated_alert(alert):
    alert_name = alert['labels'].get('alertname', 'Unknown Alert')
    correlated_alerts = CORRELATION_RULES.get(alert_name, [])
    
    for correlated_alert in correlated_alerts:
        if redis_client.exists(f"{correlated_alert}:{alert['labels'].get('instance')}"):
            return True
    return False

def handle_correlated_alert(alert):
    if is_correlated_alert(alert):
        #print(f"Alert {alert['labels'].get('alertname')} is correlated with another alert.")
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
    
    scaled_threshold = mean_usage + stddev_usage
    redis_client.set(f"{alert_name}:scaled_threshold", scaled_threshold)
    return scaled_threshold

def check_deployment_event(alert):
    recent_deployments = redis_client.lrange('recent_deployments', 0, -1)
    if recent_deployments:
        #print(f"Suppressing alert {alert['labels'].get('alertname')} due to a recent deployment event.")
        return True
    return False

def rate_limit_alert(alert, limit_time=30):  # 30 seconds instead of 60
    alert_name = alert['labels'].get('alertname', 'Unknown Alert')
    current_time = time.time()
    last_alert_time = redis_client.get(f"{alert_name}:last_sent_time")
    
    if last_alert_time:
        time_since_last_alert = current_time - float(last_alert_time)
        if time_since_last_alert < limit_time:
            return False
    
    redis_client.set(f"{alert_name}:last_sent_time", current_time)
    return True

def should_alert_be_sent(alert):
    severity = alert['labels'].get('severity', 'unknown')
    
    # Always send critical alerts
    if severity == 'critical':
        return True
    
    # Apply rate limiting and adaptive threshold checks for non-critical alerts
    if not rate_limit_alert(alert):
        return False
    
    if not is_above_adaptive_threshold(alert):
        return False
    
    return True





@app.route('/api/v2/alerts', methods=['POST'])
# def receive_alert():
#     try:
#         alert_list = request.json  # Process the list of alerts
        
#         for alert in alert_list:
#             if check_deployment_event(alert):
#                 continue

#             alert_name = alert['labels'].get('alertname', 'Unknown Alert')
#             severity = alert['labels'].get('severity', 'unknown')

#             # Rate limit alerts
#             if not rate_limit_alert(alert):
#                 continue            
            
#             # Store the alert metric for adaptive threshold analysis
#             store_metric_for_analysis(alert)
            
#             # Check if alert is correlated with another
#             if handle_correlated_alert(alert):
#                 continue
            
#             # Store the alert for trend analysis
#             store_alert_for_trend_analysis(alert)
            
#             # Auto-scale thresholds if necessary
#             auto_scale_threshold(alert_name)
            
#             # Check if the alert is above the adaptive threshold
#             if is_above_adaptive_threshold(alert):
#                 # Check rule-based filtering
#                 if severity == RULES.get(alert_name, 'critical'):
#                     send_to_slack(alert)
#                 else:
#                     print(f"Alert {alert_name} with severity {severity} suppressed by rule-based filter.")
#             else:
#                 print(f"Alert {alert_name} suppressed by adaptive threshold.")
        
#         return jsonify({"message": "Alerts processed and sent to Slack"}), 200
#     except Exception as e:
#         print(f"Error processing alert: {e}")
#         return jsonify({"message": "Failed to process alert"}), 500

@app.route('/api/v2/alerts', methods=['POST'])
def receive_alert():
    try:
        alert_list = request.json  # Process the list of alerts

        for alert in alert_list:
            # First, check if the alert should be sent based on all filtering logic
            if should_alert_be_sent(alert):
                # Store the alert metric for adaptive threshold analysis
                store_metric_for_analysis(alert)

                # Store the alert for trend analysis
                store_alert_for_trend_analysis(alert)
                
                # Auto-scale thresholds if necessary
                auto_scale_threshold(alert['labels'].get('alertname', 'Unknown Alert'))
                
                # Finally, send the alert to Slack
                send_to_slack(alert)
            else:
                print(f"Alert {alert['labels'].get('alertname', 'Unknown Alert')} suppressed by filtering logic.")
        
        return jsonify({"message": "Alerts processed and sent to Slack"}), 200
    except Exception as e:
        print(f"Error processing alert: {e}")
        return jsonify({"message": "Failed to process alert"}), 500


@app.route('/feedback', methods=['POST'])
def receive_feedback():
    feedback_data = request.json
    alert_name = feedback_data.get('alertname')
    importance = feedback_data.get('importance')
    
    # Store feedback in Redis for future reference
    redis_client.set(f"feedback:{alert_name}", importance)
    
    return jsonify({"message": "Feedback received"}), 200



if __name__ == '__main__':
    def test_redis_connection():
        try:
            test_key = "test_key"
            test_value = "test_value"
            redis_client.set(test_key, test_value)
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

    if test_redis_connection():
        # Start the Prometheus HTTP server to expose metrics
        try:
            start_http_server(9200)
            print("Prometheus metrics server started on port 9200")
        except Exception as e:
            print(f"Failed to start Prometheus server: {e}")        

        print("Starting Flask application...")
        app.run(host='0.0.0.0', port=6000, debug=True)

    else:
        print("Flask application will not start due to Redis connectivity issues.")
