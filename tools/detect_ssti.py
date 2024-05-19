import json
import requests
import argparse

def load_postman_collection(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def find_ssti_vulnerabilities(collection):
    ssti_payload = "{{1337*1337}}"
    ssti_detection_string = "1787569"

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
                    body[key] = ssti_payload
                    response = requests.post(url, headers=headers, json=body)
                    if ssti_detection_string in response.text:
                        print(f"SSTI vulnerability detected at {url} in parameter {key} using payload {ssti_payload} = {ssti_detection_string}")
                    body[key] = original_value
        elif method == "GET":
            response = requests.get(url)
            if ssti_detection_string in response.text:
                print(f"SSTI vulnerability detected at {url} using payload {ssti_payload} = {ssti_detection_string}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for Server-Side Template Injection (SSTI) vulnerabilities in a Postman collection.")
    parser.add_argument('-f', '--file', required=True, help="Path to the Postman collection file")
    args = parser.parse_args()

    collection_file_path = args.file
    collection = load_postman_collection(collection_file_path)
    find_ssti_vulnerabilities(collection)
