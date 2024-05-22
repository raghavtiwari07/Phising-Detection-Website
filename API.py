import requests

# Initialize empty lists to store URLs
clean_list = []
suspicious_list = []
malicious_list = []

# Initialize counters for each category
clean_count = 0
suspicious_count = 0
malicious_count = 0

def check_url_safety(url):
    global clean_count, suspicious_count, malicious_count, clean_list, suspicious_list, malicious_list

    # VirusTotal API
    params_vt = {'apikey': '/////////////////////////', 'resource': url}
    response_vt = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params_vt)
    json_response_vt = response_vt.json()
    if json_response_vt['positives'] == 0:
        clean_count += 1
        clean_list.append('VirusTotal')
    else:
        malicious_count += 1
        malicious_list.append('VirusTotal')

    # Google Safe Browsing API
    api_url_gs = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    params_gs = {'key': '////////////////////////////'}
    body_gs = {
        'client': {'clientId': 'UPES', 'clientVersion': '1.5.2'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    response_gs = requests.post(api_url_gs, params=params_gs, json=body_gs)
    json_response_gs = response_gs.json()
    if 'matches' in json_response_gs:
        malicious_count += 1
        malicious_list.append('GoogleSafeBrowsing')
    else:
        clean_count += 1
        clean_list.append('GoogleSafeBrowsing')

    # MetaDefender API
    api_key_md = "///////////////////////////////"
    headers_md = {"apikey": api_key_md}
    data_md = {"url": [url]}
    response_md = requests.post("https://api.metadefender.com/v4/url", headers=headers_md, json=data_md)
    json_response_md = response_md.json()
    md_safe = False
    if 'data' in json_response_md:
        for item in json_response_md['data']:
            if 'lookup_results' in item and 'detected_by' in item['lookup_results']:
                detected_by = item['lookup_results']['detected_by']
                if detected_by == 0:
                    clean_count += 1
                    clean_list.append('MetaDefender')
                else:
                    malicious_count += 1
                    malicious_list.append('MetaDefender')

    # Construct the data dictionary
    data = {
        'cleanCount': clean_count,
        'suspiciousCount': suspicious_count,
        'maliciousCount': malicious_count,
        'cleanList': clean_list,
        'suspiciousList': suspicious_list,
        'maliciousList': malicious_list
    }

    return data

# Test the function
print("Enter a URL: ")
url_to_check = input()
result = check_url_safety(url_to_check)
print("Clean Count:", result['cleanCount'])
print("Suspicious Count:", result['suspiciousCount'])
print("Malicious Count:", result['maliciousCount'])

# Print lists based on the result
if result['maliciousCount'] > 0:
    print("Malicious List:", result['maliciousList'])
else:
    print("Clean List:", result['cleanList'])
    print("Suspicious List:", result['suspiciousList'])



