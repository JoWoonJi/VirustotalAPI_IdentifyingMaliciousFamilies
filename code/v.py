import requests
import os
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

def get_report(api_key, file_id):
    url = f'https://www.virustotal.com/api/v3/files/{file_id}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get report: {response.status_code} - {response.text}")
        return None

def wait_for_report(api_key, file_id, attempts=10, delay=180):
    for attempt in range(attempts):
        report = get_report(api_key, file_id)
        if report:
            return report
        print(f"Report not ready yet. Waiting for {delay} seconds... Attempt {attempt+1}/{attempts}")
        time.sleep(delay)
    print("Failed to retrieve report after multiple attempts.")
    return None

def download_file(api_key, file_id, download_path):
    url = f'https://www.virustotal.com/api/v3/files/{file_id}/download'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers, allow_redirects=True)
    if response.status_code == 200:
        with open(download_path, 'wb') as f:
            f.write(response.content)
        print(f"File successfully downloaded to: {download_path}")
    else:
        print(f"Failed to download file: {response.status_code} - {response.text}")

def upload_get_report_download(api_key, file_path, download_dir):
    analysis_id = upload_large_file(api_key, file_path)
    if analysis_id:
        print("Uploaded successfully. Analysis ID:", analysis_id)
        report = wait_for_report(api_key, analysis_id)
        if report:
            print("Report retrieved successfully.")
            file_name = os.path.basename(file_path)
            download_path = os.path.join(download_dir, f"{analysis_id}_{file_name}")
            download_file(api_key, analysis_id, download_path)
        else:
            print("Failed to retrieve report.")
    else:
        print("Upload failed.")


api_key = 'b6ae7acd664f72d1c4df77a9658ccf2be2c9dd138198752ba4f1653ae980aa2a'
file_path = 'C:\\Users\\HP\\Desktop\\HackerJobJo_Project\\mobile_sandbox\\virustotal\\sample.apk'
download_dir = 'C:\\Users\\HP\\Desktop\\HackerJobJo_Project\\mobile_sandbox\\virustotal\\'
upload_get_report_download(api_key, file_path, download_dir)
