from flask import Flask, render_template, jsonify, request
import requests

app = Flask(__name__)

def check_url_safety(url):
    global clean_count, suspicious_count, malicious_count, clean_list, suspicious_list, malicious_list

    clean_list = []
    suspicious_list = []
    malicious_list = []
    clean_count = 0
    suspicious_count = 0
    malicious_count = 0

    params_vt = {'apikey': '//////////////', 'resource': url}
    response_vt = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params_vt)
    json_response_vt = response_vt.json()

    # List of websites checked by VirusTotal
    websites = [
        'Abusix', 'Acronis', 'ADMINUSLabs', 'AILabs (MONAPP)', 'AlienVault', 'alphaMountain.ai', 'Antiy-AVL',
        'ArcSight Threat Intelligence', 'Artists Against 419', 'benkow', 'Bfore.Ai PreCrime', 'BitDefender',
        'BlockList', 'Blueliv', 'Certego', 'Chong Lua Dao', 'CINS Army', 'CMC Threat Intelligence', 'CRDF',
        'Criminal IP', 'Cyble', 'CyRadar', 'desenmascara.me', 'DNS8', 'Dr.Web', 'EmergingThreats', 'Emsisoft',
        'ESET', 'ESTsecurity', 'Feodo Tracker', 'Forcepoint ThreatSeeker', 'Fortinet', 'G-Data'
        # Add more websites as needed...
    ]

    if json_response_vt['positives'] == 0:
        clean_count += len(websites)  # Increase the count by the number of websites
        clean_list.extend(websites)  # Add the websites to the clean list
    else:
        malicious_count += len(websites)  # Increase the count by the number of websites
        malicious_list.extend(websites)  # Add the websites to the malicious list

    # Google Safe Browsing API
    api_url_gs = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    params_gs = {'key': '\\\\\\\\\\\\\\\\\\\\'}
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
    api_key_md = "\\\\\\\\\\\\\\\\\\\\\\\\\"
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



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    url_to_check = request.args.get('url')  # Get the URL parameter from the request
    data = check_url_safety(url_to_check)  # Call the check_url_safety function with the URL
    return render_template('dashboard.html', data=data)

@app.route('/data')
def get_data():
    # Return the data as JSON
    url_to_check = request.args.get('url')  # Get the URL parameter from the request
    data = check_url_safety(url_to_check)  # Call the check_url_safety function with the URL
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)



