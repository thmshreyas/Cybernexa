import requests

url = "https://check-ssl.p.rapidapi.com/sslcheck"

querystring = {"domain":"amazon.com"}

headers = {
    "X-RapidAPI-Key": "4c38c122fcmsh82e6abd326c09efp1b9f96jsne2361a2bb7c7",
    "X-RapidAPI-Host": "check-ssl.p.rapidapi.com"
}

response = requests.get(url, headers=headers, params=querystring)

# Check if the request was successful (status code 200)
if response.status_code == 200:
    # Extract the required fields
    data = response.json()
    required_fields = {
        
        "canBeSelfSigned": data["canBeSelfSigned"],
        "isWildCard": data["isWildCard"],
        "isExpired": data["isExpired"],
        "message": data["message"],
        "expiry": data["expiry"],
        "daysLeft": data["daysLeft"],
        "lifespanInDays": data["lifespanInDays"],
        "issuer": data["issuer"]
    }
    # Print the required fields
    for key, value in required_fields.items():
        print(f"{key}: {value}")
else:
    print("Failed to retrieve data. Status code:", response.status_code)