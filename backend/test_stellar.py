from stellar_sdk import Server
import os
from dotenv import load_dotenv

load_dotenv('../.env')

server = Server("https://horizon-testnet.stellar.org")
PUBLIC_KEY = os.getenv('STELLAR_PUBLIC_KEY')

try:
    account = server.accounts().account_id(PUBLIC_KEY).call()
    print("✅ Connected to Stellar Testnet!")
    print(f"Account: {account['id']}")
    for balance in account['balances']:
        print(f"Balance: {balance['balance']} {balance['asset_type']}")
except Exception as e:
    print(f"❌ Error: {e}")