from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict


def generate_contract_and_pdf_hashes(contract_input: str, pdf_path: str) -> Dict[str, str]:
    """
    Generate SHA-256 hashes for:
      1) Contract input text
      2) PDF file bytes

    Returns:
    {
      "contract_hash": "<sha256 hex>",
      "pdf_hash": "<sha256 hex>"
    }
    """
    contract_hash = hashlib.sha256(contract_input.encode("utf-8")).hexdigest()

    file_path = Path(pdf_path)
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError(f"PDF file not found: {pdf_path}")

    pdf_hasher = hashlib.sha256()
    with file_path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(8192), b""):
            pdf_hasher.update(chunk)

    return {
        "contract_hash": contract_hash,
        "pdf_hash": pdf_hasher.hexdigest(),
    }
