#!/usr/bin/env python3

import sys
import json
import requests

def main():
    try:
        # Wazuh passes the alert file path as the first argument
        alert_file_path = sys.argv[1]
        hook_url = sys.argv[3]

        # Load alert JSON from file
        with open(alert_file_path) as f:
            alert = json.load(f)

        # Send POST to your webhook endpoint
        headers = {'Content-Type': 'application/json'}
        response = requests.post(hook_url, json=alert, headers=headers, timeout=10)

        if response.status_code != 200:
            print(f"Webhook error: {response.status_code} - {response.text}", file=sys.stderr)
    except Exception as e:
        print(f"Webhook failed: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
