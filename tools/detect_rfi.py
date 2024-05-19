import json
import requests
import argparse

def load_postman_collection(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def find_rfi_vulnerabilities(collection):
    rfi_payload = "http://127.0.0.1/rfi.checker"
    detection_string = "6363fe744f74ee8f280958ab2f185dde"

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
                    body[key] = rfi_payload
                    response = requests.post(url, headers=headers, json=body)
                    if detection_string in response.text:
                        print(f"RFI vulnerability detected at {url} in parameter {key} using payload {rfi_payload}")
                    body[key] = original_value
        elif method == "GET":
            response = requests.get(url, params={"file": rfi_payload})
            if detection_string in response.text:
                print(f"RFI vulnerability detected at {url} using payload {rfi_payload}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for Remote File Inclusion (RFI) vulnerabilities in a Postman collection.")
    parser.add_argument('-f', '--file', required=True, help="Path to the Postman collection file")
    args = parser.parse_args()

    collection_file_path = args.file
    collection = load_postman_collection(collection_file_path)
    find_rfi_vulnerabilities(collection)
