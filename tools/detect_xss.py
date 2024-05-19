import json
import requests
import argparse

def load_postman_collection(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def find_xss_vulnerabilities(collection):
    xss_payload = "<script>alert('xss-detected-6363fe744f74ee8f280958ab2f185dde')</script>"

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
                    body[key] = xss_payload
                    response = requests.post(url, headers=headers, json=body)
                    if xss_payload in response.text:
                        print(f"XSS vulnerability detected at {url} in parameter {key} using payload {xss_payload}")
                    body[key] = original_value
        elif method == "GET":
            response = requests.get(url)
            if xss_payload in response.text:
                print(f"XSS vulnerability detected at {url} using payload {xss_payload}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for Cross-Site Scripting (XSS) vulnerabilities in a Postman collection.")
    parser.add_argument('-f', '--file', required=True, help="Path to the Postman collection file")
    args = parser.parse_args()

    collection_file_path = args.file
    collection = load_postman_collection(collection_file_path)
    find_xss_vulnerabilities(collection)
