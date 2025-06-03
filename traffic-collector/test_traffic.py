#!/usr/bin/env python3
import requests
import time
import sys

def send_request():
    try:
        response = requests.get('https://www.baidu.com')
        print(f"Request sent, status code: {response.status_code}, content length: {len(response.content)} bytes")
    except Exception as e:
        print(f"Error sending request: {e}")

def main():
    print("Starting to send requests to baidu.com...")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            send_request()
            time.sleep(1)  # 每秒发送一次请求
    except KeyboardInterrupt:
        print("\nStopping requests...")
        sys.exit(0)

if __name__ == "__main__":
    main() 