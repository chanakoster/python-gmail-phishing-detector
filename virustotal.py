import time
import requests
from config import BASE_URL, VT_API_KEY


def get_domain_report(domain):
    print ("🐕Fetching domain report")

    url = f"{BASE_URL}/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        vt_json_report = requests.get(url, headers=headers)
        vt_json_report.raise_for_status()
        print ("🐶Successfully fetched report")
        return vt_json_report.json()

    except requests.RequestException as e:
        print(f"❌ Domain VT error: {e}")
        return None


def submit_url(url_to_scan):
    print("🐤Submitting POST request for URL")
    url = f"{BASE_URL}/urls"
    headers = {"x-apikey": VT_API_KEY}
    try:
        res = requests.post(url, headers=headers, data={"url": url_to_scan})
        res.raise_for_status()
        vt_id = (res.json()["data"]["id"])
        print ("🐥POST request successful")
        return vt_id
    except requests.RequestException as e:
        print(f"❌ URL submission error: {e}")
        return None


def get_url_report(scan_id, retries=5, delay=3):
    print("🐕Fetching url report")
    url = f"{BASE_URL}/analyses/{scan_id}"
    headers = {"x-apikey": VT_API_KEY}

    for attempt in range(retries):
        try:
            res = requests.get(url, headers=headers)
            res.raise_for_status()
            data = res.json()

            # Check if analysis is complete
            if data.get("data", {}).get("attributes", {}).get("status") == "completed":
                print("✅ URL analysis completed")
                return data
            else:
                print(f"⏳ Waiting for analysis to complete (Attempt {attempt+1})")
                time.sleep(delay)

        except requests.RequestException as e:
            print(f"❌ URL report fetch error: {e}")
            return None

    print("⚠️ Analysis did not complete in time.")
    return None


def upload_file(file_bytes):
    print("🖐️Submitting POST request for file")
    url = f"{BASE_URL}/files"
    headers = {
        "x-apikey": VT_API_KEY
    }
    files = {"file": ("attachment", file_bytes)}
    try:
        res = requests.post(url, headers=headers, files=files)
        res.raise_for_status()
        print("👏POST request successful")
        return res.json()["data"]["id"]
    except requests.RequestException as e:
        print(f"❌ File upload error: {e}")
        return None

def get_file_report(file_id):
    print("⚾Fetching file report")
    url = f"{BASE_URL}/analyses/{file_id}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        print ("⚽Successfully fetched report")
        return res.json()
    except requests.RequestException as e:
        print(f"❌ File report error: {e}")
        return None

