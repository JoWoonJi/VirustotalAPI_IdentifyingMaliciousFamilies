import requests
import os
import time

def get_upload_url(api_key):
    url = 'https://www.virustotal.com/api/v3/files/upload_url'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        upload_url = response.json().get('data', '')
        return upload_url
    else:
        print(f"Failed to get upload URL: {response.status_code} - {response.text}")
        return None

def upload_large_file(api_key, file_path):
    upload_url = get_upload_url(api_key)
    if not upload_url:
        return None
    
    with open(file_path, 'rb') as file:
        files = {'file': file}
        headers = {'x-apikey': api_key}
        response = requests.post(upload_url, files=files, headers=headers)
    if response.status_code == 200:
        analysis_id = response.json().get('data', {}).get('id')
        print(f"Analysis ID: {analysis_id}")
        return analysis_id
    else:
        print(f"File upload failed: {response.status_code} - {response.text}")
        return None

def get_file_report(api_key, analysis_id):
    url = f"https://www.virustotal.com/api/v3/files/{analysis_id}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        report = response.json()
        attributes = report.get('data', {}).get('attributes', {})
        last_analysis_results = attributes.get('last_analysis_results', {})
        popular_threat_classification = attributes.get('popular_threat_classification', {})

        print("Malicious Results:")
        for engine_name, analysis_result in last_analysis_results.items():
            if analysis_result.get('category', '') == 'malicious':
                print(f"{engine_name}: {analysis_result.get('result')}")

        print("\nPopular Threat Label:", popular_threat_classification.get('suggested_threat_label', 'N/A'))

        print("\nThreat Categories:")
        for category in popular_threat_classification.get('popular_threat_category', []):
            print(f"  - {category['value']} (Count: {category['count']})")

        print("\nFamily Labels:")
        for name in popular_threat_classification.get('popular_threat_name', []):
            print(f"  - {name['value']} (Count: {name['count']})")

    else:
        print(f"Failed to get report: {response.status_code} - {response.text}")

def get_popular_threat_categories(api_key):
    url = "https://www.virustotal.com/api/v3/popular_threat_categories"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        categories = response.json()
        print("\nPopular Threat Categories:")
        for category in categories.get('data', []):
            print(f"  - {category.get('id', 'Unknown')} : {category.get('type', 'Unknown')}")
    else:
        print(f"Failed to get popular threat categories: {response.status_code} - {response.text}")

def wait_for_report_completion(api_key, analysis_id, timeout=300, interval=15):
    start_time = time.time()
    while True:
        report = get_file_report(api_key, analysis_id)
        if report and report['data']['attributes']['status'] == 'completed':
            return report
        elif time.time() - start_time > timeout:
            print("Timed out waiting for report completion.")
            return None
        else:
            print("Report not ready yet. Waiting...")
            time.sleep(interval)

def extract_info_from_report(report):
    results = report['data']['attributes']['results']
    malicious_results = {engine: result['result'] for engine, result in results.items() if result['category'] == 'malicious'}
    print("Malicious results:")
    for engine, result in malicious_results.items():
        print(f"{engine}: {result}")

# Usage
api_key = ''
file_path = 'C:\\Users\\HP\\Desktop\\HackerJobJo_Project\\mobile_sandbox\\virustotal\\sample.apk'
analysis_id = upload_large_file(api_key, file_path)
get_file_report(api_key, analysis_id)
get_popular_threat_categories(api_key)
if analysis_id:
    report = wait_for_report_completion(api_key, analysis_id)
    if report:
        print("Report retrieved successfully.")
        extract_info_from_report(report)
    else:
        print("Failed to retrieve report.")
else:
    print("Upload failed.")
