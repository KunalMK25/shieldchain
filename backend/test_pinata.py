import requests
import os
from dotenv import load_dotenv

load_dotenv('../.env')

API_KEY    = os.getenv('PINATA_API_KEY')
API_SECRET = os.getenv('PINATA_SECRET_KEY')

url = "https://api.pinata.cloud/data/testAuthentication"
headers = {
    "pinata_api_key": API_KEY,
    "pinata_secret_api_key": API_SECRET
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    print("✅ Pinata IPFS connected!")
    print(response.json())
else:
    print(f"❌ Error: {response.text}")