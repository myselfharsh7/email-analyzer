import email
from email import policy
from email.parser import BytesParser
import re
import virustotal_python # type: ignore
from base64 import urlsafe_b64encode
import hashlib
import dns.resolver
import requests

def read_eml_file(file_content):
    msg = BytesParser(policy=policy.default).parsebytes(file_content)
    return msg

def get_ip_details(ip_address):
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    try:
        response = requests.get(url)
        data = response.json()
        if data["status"] == "fail":
            return {"error": data["message"]}
        return data
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def extract_email_info(msg):
    received_headers = msg.get('Received', '')
    ip_geolocation = analyze_ip_geolocation(received_headers)
    email_info = {
        "from": msg.get('From', ''),
        "to": msg.get('To', ''),
        "x-originating-ip": msg.get('X-Originating-IP', ''),
        "message-id": msg.get('Message-ID', ''),
        "spf-record": msg.get('Authentication-Results', '').lower().find('spf=pass') != -1,
        "dmarc-record": msg.get('Authentication-Results', '').lower().find('dmarc=pass') != -1,
        "spoofed": msg.get('Authentication-Results', '').lower().find('spf=fail') != -1,
        "ip-address": received_headers,
        "sender-client": msg.get('X-Mailer', ''),
        "spoofed-mail": msg.get('Authentication-Results', '').lower().find('spf=softfail') != -1,
        "dt": msg.get('Date', ''),
        "content-type": msg.get_content_type(),
        "subject": msg.get('Subject', ''),
        "return-path": msg.get('Return-Path', ''),
        "mx_records": get_mx_records(msg.get('From', '')),
        "ip-geolocation": ip_geolocation
    }
    return email_info

def analyze_ip_geolocation(received_headers):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ip_matches = ip_pattern.findall(received_headers)
    if ip_matches:
        ip = ip_matches[-1]
        return get_ip_details(ip)
    return None

def get_mx_records(email_address):
    domain = email_address.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [{"exchange": record.exchange.to_text(), "preference": record.preference} for record in mx_records]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        return [{"error": str(e)}]

def extract_message_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain' or content_type == 'text/html':
                return part.get_payload(decode=True).decode('utf-8', 'ignore')
    else:
        return msg.get_payload(decode=True).decode('utf-8', 'ignore')

def has_attachment(part):
    content_disposition = part.get("Content-Disposition", "")
    return content_disposition.startswith("attachment")

def check_attachments(msg):
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if has_attachment(part):
                filename = part.get_filename()
                if filename:
                    attachments.append((filename, part))
    return attachments

def extract_urls(text):
    url_pattern = re.compile(
        r'(?i)\b((?:(?:https?://|ftp://|www\d{0,3}[.])?[a-z0-9.-]+\.[a-z]{2,4}(?:/[^\s()<>]*)?))'
    )
    urls = re.findall(url_pattern, text)
    return urls

def check_for_urls(msg):
    email_body = extract_message_body(msg)
    urls = extract_urls(email_body)
    return urls

def url_scan(url):
    with virustotal_python.Virustotal("api key") as vtotal:
        try:
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            if resp.status_code == 200:
                url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
                report = vtotal.request(f"urls/{url_id}")
                reputation = report.data['attributes']['reputation']
                harmless = report.data['attributes']['last_analysis_stats']['harmless']
                malicious = report.data['attributes']['last_analysis_stats']['malicious']
                suspicious = report.data['attributes']['last_analysis_stats']['suspicious']
                sus = int(malicious) + int(suspicious)
                return {
                    "url": url,
                    "reputation": reputation,
                    "harmless": harmless,
                    "malicious": sus
                }
            elif resp.status_code == 404:
                return {"url": url, "error": "Page not found"}
            else:
                return {"url": url, "error": f"Error: {resp.status_code} - {resp.text}"}
        except virustotal_python.VirustotalError as err:
            return {"url": url, "error": f"Failed to send URL: {url} for analysis and get the report: {err}"}

def get_file_hashes(file_content):
    md5_hash = hashlib.md5()
    md5_hash.update(file_content)
    return md5_hash.hexdigest()

def attachment_scan(md5_hash):
    with virustotal_python.Virustotal("api key") as vtotal:
        try:
            report = vtotal.request(f"files/{md5_hash}")
            harmless = report.data['attributes']['last_analysis_stats']['harmless']
            malicious = report.data['attributes']['last_analysis_stats']['malicious']
            suspicious = report.data['attributes']['last_analysis_stats']['suspicious']
            sus = int(malicious) + int(suspicious)
            return {
                "md5": md5_hash,
                "harmless": harmless,
                "malicious": sus
            }
        except virustotal_python.VirustotalError as err:
            return {"md5": md5_hash, "error": f"Failed to get report for hash: {md5_hash} - {err}"}

def analyze_email(file):
    file_content = file.read()
    msg = read_eml_file(file_content)
    email_info = extract_email_info(msg)
    urls = check_for_urls(msg)
    url_scans = [url_scan(url) for url in urls]
    attachments = check_attachments(msg)
    attachment_scans = []
    for filename, part in attachments:
        attachment_content = part.get_payload(decode=True)
        md5_hash = get_file_hashes(attachment_content)
        scan_result = attachment_scan(md5_hash)
        attachment_scans.append({
            "filename": filename,
            "scan_result": scan_result
        })
    return {
        "email_info": email_info,
        "url_scans": url_scans,
        "attachment_scans": attachment_scans
    }
