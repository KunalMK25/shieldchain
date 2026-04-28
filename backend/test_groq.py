from groq import Groq
import os
from dotenv import load_dotenv

load_dotenv('../.env')

client = Groq(api_key=os.getenv('GROQ_API_KEY'))

response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[
        {
            "role": "user",
            "content": "Say exactly: ShieldChain Groq API connected successfully!"
        }
    ]
)

print(response.choices[0].message.content)