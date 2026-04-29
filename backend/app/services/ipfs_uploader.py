from __future__ import annotations

import os
from pathlib import Path
from typing import Dict

import requests
from dotenv import load_dotenv


env_path = Path(__file__).resolve().parents[3] / ".env"
load_dotenv(dotenv_path=env_path)


def upload_pdf_to_ipfs(pdf_path: str) -> Dict[str, str]:
    """
    Upload a generated PDF file to IPFS via Pinata.
    Returns:
    {
      "cid": "<ipfs cid>",
      "url": "https://gateway.pinata.cloud/ipfs/<ipfs cid>"
    }
    """
    api_key = os.getenv("PINATA_API_KEY")
    api_secret = os.getenv("PINATA_SECRET_KEY")
    if not api_key or not api_secret:
        raise ValueError("Pinata credentials missing. Set PINATA_API_KEY and PINATA_SECRET_KEY in .env")

    path = Path(pdf_path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"PDF file not found: {pdf_path}")

    pinata_url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "pinata_api_key": api_key,
        "pinata_secret_api_key": api_secret,
    }

    with path.open("rb") as file_obj:
        files = {
            "file": (path.name, file_obj, "application/pdf"),
        }
        response = requests.post(pinata_url, headers=headers, files=files, timeout=60)

    if response.status_code != 200:
        raise RuntimeError(f"Pinata upload failed ({response.status_code}): {response.text}")

    data = response.json()
    cid = data.get("IpfsHash")
    if not cid:
        raise RuntimeError("Pinata upload succeeded but no IpfsHash returned")

    return {
        "cid": cid,
        "url": f"https://gateway.pinata.cloud/ipfs/{cid}",
    }
