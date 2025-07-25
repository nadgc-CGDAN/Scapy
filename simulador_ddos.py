import requests
import time

ip = "http://localhost:5000"
for i in range(200):
    try:
        requests.get(ip)
    except:
        pass
    time.sleep(0.05)
