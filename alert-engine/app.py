from flask import Flask, request, jsonify
import requests
import redis
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

app = Flask(__name__)

# Slack configuration
slack_webhook_url = "https://hooks.slack.com/services/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"


# Redis configuration
redis_client = redis.StrictRedis(host='redis', port=6379, db=0, decode_responses=True)

# Rule-based filtering rules
RULES = {
    "HighCPUUsage": "critical"
}

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


@app.route('/api/v2/alerts', methods=['POST'])
def receive_alert():
    try:
        alert_list = request.json  # Since the alert is a list, process it as such
        
        # Loop through the list of alerts and process each one
        for alert in alert_list:
            send_to_slack(alert)
        
        return jsonify({"message": "Alerts processed and sent to Slack"}), 200
    except Exception as e:
        print(f"Error processing alert: {e}")
        return jsonify({"message": "Failed to process alert"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6001)
