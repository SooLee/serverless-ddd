import requests
import time

# replace URL with your API endpoint URL!
URL = 'https://56830eay01.execute-api.us-east-1.amazonaws.com/api'

# make a GET request at 1-second interval (~45 requests per minute) for ~27 minutes
for i in range(1, 1200):
    res = requests.get(URL)
    print("status_code=" + str(res.status_code))
    print("content=" + res.content.decode('utf-8'))
    time.sleep(1)

