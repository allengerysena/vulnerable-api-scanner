import json
import requests
import argparse

def load_postman_collection(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def find_host_header_injection_vulnerabilities(collection):
    injection_host = "127.0.0.1:1337"

    for item in collection['item']:
        request = item['request']
        url = request['url']['raw']
        method = request['method']

        if method == "POST" and request['header']:
            headers = {header['key']: header['value'] for header in request['header']}
            headers['Host'] = injection_host
            if 'Content-Type' in headers and headers['Content-Type'] == 'application/json':
                body = json.loads(request['body']['raw'])
                response = requests.post(url, headers=headers, json=body)
                if injection_host in response.text:
                    print(f"Host Header Injection vulnerability detected at {url} using injection host {injection_host}")
        elif method == "GET":
            headers = {header['key']: header['value'] for header in request['header']} if 'header' in request else {}
            headers['Host'] = injection_host
            response = requests.get(url, headers=headers)
            if injection_host in response.text:
                print(f"Host Header Injection vulnerability detected at {url} using injection host {injection_host}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for Host Header Injection vulnerabilities in a Postman collection.")
    parser.add_argument('-f', '--file', required=True, help="Path to the Postman collection file")
    args = parser.parse_args()

    collection_file_path = args.file
    collection = load_postman_collection(collection_file_path)
    find_host_header_injection_vulnerabilities(collection)
