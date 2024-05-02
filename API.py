import requests

def check_url_safety(url):
    # Initialize an empty dictionary to store results
    safety_results = {}

    # VirusTotal API
    params_vt = {'apikey': '6e125786da905f2c99d4cf8ca3c3331edbfe3bf2f1726c3caf7006838b5a72d8', 'resource': url}
    response_vt = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params_vt)
    json_response_vt = response_vt.json()
    safety_results['VirusTotal'] = json_response_vt['positives'] == 0

    # Google Safe Browsing API
    api_url_gs = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    params_gs = {'key': 'AIzaSyBQdQt7rf0ZGWcU-6MNwgyNSpDFn8Qhxfs'}
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
    safety_results['GoogleSafeBrowsing'] = 'matches' not in json_response_gs

    # MetaDefender API
    api_key_md = "e0bf7e3d573753730e829e2c5144b846"  # Replace with your actual API key
    headers_md = {"apikey": api_key_md}
    data_md = {"url": [url]}
    response_md = requests.post("https://api.metadefender.com/v4/url", headers=headers_md, json=data_md)
    json_response_md = response_md.json()
    md_safe = False
    if 'data' in json_response_md:
        for item in json_response_md['data']:
            if 'lookup_results' in item and 'detected_by' in item['lookup_results']:
                detected_by = item['lookup_results']['detected_by']
                md_safe = detected_by == 0
                break
    safety_results['MetaDefender'] = md_safe

    return safety_results

# Test the function
url_to_check = 'www.google.com'
result = check_url_safety(url_to_check)
print(result)
