import requests

ip = "192.168.153.2"
def calculate_length(data):
    count = 0
    for x, y in data.items():
        count += len(x) + len(y) + 2
    return count - 1

url = "http://" + ip + "/cgi-bin/cstecgi.cgi"

cookie = {"Cookie":"SESSION_ID=2:1721039211:2"}

data = {
    "{payload}",
}

data["topicurl"] = "{URI}"

try:
    res = requests.post(url=url, headers=headers, data=data, timeout=500, verify=False)
    print(res.status_code)
except requests.exceptions.Timeout:
    print("TIMEOUT")
except Exception as e:
    print("EXCEPTION:", str(e))