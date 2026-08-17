# ai_core/src/extract_ioc.py
import re
import ipaddress

def extract_ips(text):
    """Dùng Regex để tìm các địa chỉ IPv4."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    found = re.findall(ip_pattern, text)
    valid_ips = []
    for ip in found:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            continue
    return list(set(valid_ips))

def extract_domains(text):
    """Dùng Regex để tìm Domain (dạng: evil.com, sub.evil.org)."""
    domain_pattern = r'\b([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)\b'
    found = re.findall(domain_pattern, text)
    domains = [match[0] for match in found]
    return list(set(domains))

def extract_hashes(text):
    """Dùng Regex để tìm MD5, SHA1, SHA256."""
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    
    hashes = []
    hashes.extend(re.findall(md5_pattern, text))
    hashes.extend(re.findall(sha1_pattern, text))
    hashes.extend(re.findall(sha256_pattern, text))
    return list(set(hashes))

def extract_emails(text):
    """Dùng Regex để tìm Email."""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    found = re.findall(email_pattern, text)
    return list(set(found))

def extract_all_iocs(text):
    """Wrapper để gọi tất cả các hàm trên."""
    return {
        "ips": extract_ips(text),
        "domains": extract_domains(text),
        "hashes": extract_hashes(text),
        "emails": extract_emails(text)
    }

if __name__ == "__main__":
    test_text = """
    Suspicious IP 192.168.1.100 connected to evil-malware.com. 
    The file hash is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (SHA256). 
    Contact admin@hacker.xyz for more info.
    """
    print("IOC tìm thấy:", extract_all_iocs(test_text))