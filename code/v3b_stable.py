import requests
import time
import json

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

def upload_file(api_key, file_path, upload_url):
    headers = {'x-apikey': api_key}
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(upload_url, headers=headers, files=files)
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

def get_popular_threat_categories(api_key):
    url = "https://www.virustotal.com/api/v3/popular_threat_categories"
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        categories = response.json()
        categories_str = json.dumps(categories, indent=4)
        print("Popular Threat Categories:")
        print(categories_str)  # 콘솔에 출력
        # 파일에 저장
        with open('popular_threat_categories.txt', 'w') as file:
            file.write(categories_str)
        print("Popular threat categories saved to popular_threat_categories.txt")
    else:
        print(f"Failed to get popular threat categories: {response.status_code} - {response.text}")

def upload_and_get_report(api_key, file_path):
    upload_url = get_upload_url(api_key)
    if not upload_url:
        print("Failed to obtain upload URL.")
        return

    analysis_id = upload_file(api_key, file_path, upload_url)
    if not analysis_id:
        print("Failed to upload file.")
        return

    # Wait for some time to allow analysis to complete
    print("Waiting for analysis to complete...")
    time.sleep(30)  # Adjust this delay as necessary

    report = get_report(api_key, analysis_id)
    if report:
        print("Report retrieved successfully.")
        # 보고서를 JSON 문자열로 변환
        report_str = json.dumps(report, indent=4)
        
        # 보고서를 파일에 저장
        with open('report.txt', 'w') as file:
            file.write(report_str)
        
        print("Report saved to report.txt")
        get_popular_threat_categories(api_key)
        return report
    else:
        print("Failed to retrieve report.")
        return None

# Usage
api_key = 'b6ae7acd664f72d1c4df77a9658ccf2be2c9dd138198752ba4f1653ae980aa2a'
file_path = 'C:\\Users\\HP\\Desktop\\HackerJobJo_Project\\mobile_sandbox\\virustotal\\sample.apk'
report = upload_and_get_report(api_key, file_path)
if report:
    print(report)  # Or process the report as needed
