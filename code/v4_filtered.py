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

def get_report(api_key, analysis_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get report: {response.status_code} - {response.text}")
        return None

def wait_for_report_completion(api_key, analysis_id, timeout=300, interval=15):
    start_time = time.time()
    while True:
        report = get_report(api_key, analysis_id)
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
api_key = 'b6ae7acd664f72d1c4df77a9658ccf2be2c9dd138198752ba4f1653ae980aa2a'
file_path = 'C:\\Users\\HP\\Desktop\\HackerJobJo_Project\\mobile_sandbox\\virustotal\\sample.apk'
analysis_id = upload_large_file(api_key, file_path)
if analysis_id:
    report = wait_for_report_completion(api_key, analysis_id)
    if report:
        print("Report retrieved successfully.")
        extract_info_from_report(report)
    else:
        print("Failed to retrieve report.")
else:
    print("Upload failed.")
