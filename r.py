
# Virus Total
# import requests

# def is_url_safe(url):
#     params = {'apikey': '6e125786da905f2c99d4cf8ca3c3331edbfe3bf2f1726c3caf7006838b5a72d8', 'resource': url}
#     response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
#     json_response = response.json()
#     return json_response['positives'] == 0

# print(is_url_safe('https://wer.gsesrt.cloudns.biz/'))

# --------------------------------------------------------------------------------------------------------------

# # Google safe brwoing api: AIzaSyBQdQt7rf0ZGWcU-6MNwgyNSpDFn8Qhxfs
# import requests
# import json

# def check_url(url):
#     # Define the API request URL
#     api_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

#     # Define the parameters for the API request
#     params = {
#         'key': 'AIzaSyBQdQt7rf0ZGWcU-6MNwgyNSpDFn8Qhxfs',
#     }

#     # Define the body for the API request
#     body = {
#         'client': {
#             'clientId': 'UPES',
#             'clientVersion': '1.5.2'
#         },
#         'threatInfo': {
#             'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
#             'platformTypes': ['ANY_PLATFORM'],
#             'threatEntryTypes': ['URL'],
#             'threatEntries': [{'url': url}]
#         }
#     }

#     # Send the POST request to the API
#     response = requests.post(api_url, params=params, json=body)

#     # Parse the JSON response
#     json_response = response.json()

#     # Check if any threats were found
#     if 'matches' in json_response:
#         return False  # The URL is not safe
#     else:
#         return True  # The URL is safe

# # Test the function
# print(check_url('https://wer.gsesrt.cloudns.biz/'))



# --------------------------------------------------------------------------------------------------------


# # MetaDefender API key: e0bf7e3d573753730e829e2c5144b846

# import requests

# def scan_url(url, api_key):
#     headers = {
#         "apikey": api_key
#     }
#     data = {
#         "url": [url]  # Wrap the URL in a list to make it an array
#     }
#     response = requests.post("https://api.metadefender.com/v4/url", headers=headers, json=data)
#     json_response = response.json()

#     # Check if any threats were found
#     if 'data' in json_response:
#         for item in json_response['data']:
#             if 'lookup_results' in item and 'detected_by' in item['lookup_results']:
#                 detected_by = item['lookup_results']['detected_by']
#                 if detected_by == 0:
#                     return True  # The URL is safe
#                 else:
#                     return False  # The URL is not safe
#     return None  # The scan result is not available

# # Test the function
# api_key = "e0bf7e3d573753730e829e2c5144b846"  # Replace with your actual API key
# url = "http://example.com"  # Replace with the URL you want to scan
# print(scan_url(url, api_key))


# -----------------------------------------------------------------------------------------------------------


# # Sophos Client Id: 21a87de7-dc9c-49cd-9a94-523ddae54867
# # client secret : f8a249ebb4613829cd5b3f11e47c75694c4d753fa6377edc1e673b0aa6d009b1967cf93ddb016a064d2fba11c3fec67ed572

# import requests

# # Sophos API endpoint
# url = "https://api3.sophos.com/"

# # Your Sophos API credentials
# client_id = "21a87de7-dc9c-49cd-9a94-523ddae54867"
# client_secret = "f8a249ebb4613829cd5b3f11e47c75694c4d753fa6377edc1e673b0aa6d009b1967cf93ddb016a064d2fba11c3fec67ed572"

# def check_website(website_url):
#     # Prepare the headers with the client credentials
#     headers = {
#         'Authorization': f'Bearer {client_id}:{client_secret}',
#         'Content-Type': 'application/json'
#     }

#     # Prepare the payload with the website URL
#     payload = {
#         'url': website_url
#     }

#     # Send a POST request to the Sophos API
#     response = requests.post(url, headers=headers, json=payload)

#     # If the response status code is 200, the website is not a phishing site
#     if response.status_code == 200:
#         print("True")
#     # If the response status code is not 200, the website is a phishing site
#     else:
#         print("False")

# # Test the function with a website URL
# check_website("https://example.com")
