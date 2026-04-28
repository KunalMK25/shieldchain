from google import genai
import os
from dotenv import load_dotenv

load_dotenv('../.env')

client = genai.Client(api_key=os.getenv('GEMINI_API_KEY'))

response = client.models.generate_content(
    model="gemini-2.0-flash",
    contents="Say exactly: ShieldChain Gemini API connected successfully!"
)

print(response.text)