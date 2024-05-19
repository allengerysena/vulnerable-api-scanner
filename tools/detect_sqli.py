import json
import requests
import argparse

def load_postman_collection(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def find_sql_injection_vulnerabilities(collection):
    sql_payloads = [
        "' --",
        "' #",
        "'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "' HAVING 1=1 --",
        "' GROUP BY table.columnfromerror1 HAVING 1=1 --",
        "' GROUP BY table.columnfromerror1, columnfromerror2 HAVING 1=1 --"
    ]
    detection_string = "syntax error"

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
                    for payload in sql_payloads:
                        body[key] = original_value + payload
                        response = requests.post(url, headers=headers, json=body)
                        if detection_string in response.text:
                            print(f"Potential SQL Injection vulnerability detected at {url} in parameter {key} using payload {payload}")
                            break
                        body[key] = original_value
        elif method == "GET":
            for payload in sql_payloads:
                params = {param['key']: param['value'] + payload for param in request['url'].get('query', [])}
                response = requests.get(url, params=params)
                if detection_string in response.text:
                    print(f"Potential SQL Injection vulnerability detected at {url} using payload {payload}")
                    break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for SQL Injection vulnerabilities in a Postman collection.")
    parser.add_argument('-f', '--file', required=True, help="Path to the Postman collection file")
    args = parser.parse_args()

    collection_file_path = args.file
    collection = load_postman_collection(collection_file_path)
    find_sql_injection_vulnerabilities(collection)
