import requests
import time

def get_upload_url(api_key):
    url = 'https://www.virustotal.com/api/v3/files/upload_url'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('data', '')
    else:
        print(f"Failed to get upload URL: {response.status_code} - {response.text}")
        return None

def upload_large_file(api_key, file_path):
    upload_url = get_upload_url(api_key)
    if not upload_url:
        return None
    
    headers = {'x-apikey': api_key}
    with open(file_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(upload_url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json().get('data', {}).get('id')
    else:
        print(f"File upload failed: {response.status_code} - {response.text}")
        return None

def get_report(api_key, file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get report: {response.status_code} - {response.text}")
        return None

def wait_for_report(api_key, file_id, attempts=10, delay=30):
    for attempt in range(attempts):
        report = get_report(api_key, file_id)
        if report:
            return report
        print(f"Report not ready yet. Waiting for {delay} seconds... Attempt {attempt+1}/{attempts}")
        time.sleep(delay)
    print("Failed to retrieve report after multiple attempts.")
    return None

def upload_get_report(api_key, file_path):
    analysis_id = upload_large_file(api_key, file_path)
    if analysis_id:
        print("Uploaded successfully. Analysis ID:", analysis_id)
        report = wait_for_report(api_key, analysis_id)
        if report:
            print("Report retrieved successfully.")
            # 여기에서 보고서 처리 로직을 추가하세요.
        else:
            print("Failed to retrieve report.")
    else:
        print("Upload failed.")

# Usage
api_key = ''
file_path = 'C:\\Users\\HP\\Desktop\\HackerJobJo_Project\\mobile_sandbox\\virustotal\\sample.apk'
file_hash = '82d644a1f3bba120327e7eb6029f6b986c95c35f0c40cd43001f2dbedee2ee6f'  # SHA-256 해시 값
upload_get_report(api_key, file_path)
