# ShieldChain


---

## Description

ShieldChain is an AI-powered Soroban smart contract security scanner with immutable on-chain audit anchoring. The platform combines cutting-edge AI analysis (Groq LLaMA 3.3 70B), decentralized storage (Pinata IPFS), and blockchain verification (Stellar Testnet) to provide developers with trustless, permanent security audit records for their Soroban smart contracts.

### Key Features

- **AI-Powered Analysis**: Leverages Groq's LLaMA 3.3 70B model to detect vulnerabilities, assess risk scores, and generate exploit narratives
- **On-Chain Proof**: Immutable audit records anchored to Stellar Testnet via the AuditRegistry Soroban smart contract
- **IPFS Storage**: Professionally styled PDF audit reports permanently stored on IPFS via Pinata
- **Real-Time Verification**: Anyone can independently verify that a contract was audited by querying the blockchain
- **Audit History Tracking**: Complete audit history with risk score trends over time
- **< 60 Second Analysis**: Fast, comprehensive security scans with detailed vulnerability breakdowns
- **100% Free**: Open-source platform with no usage fees

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Smart Contract** | Soroban / Rust 1.91 | Immutable audit registry on Stellar Testnet |
| **Backend** | FastAPI / Python 3.10+ | API orchestration, AI analysis, PDF generation |
| **Frontend** | React / TypeScript | Interactive SPA with Monaco editor and data visualization |
| **AI Model** | Groq LLaMA 3.3 70B | Vulnerability detection and risk assessment |
| **Blockchain** | Stellar Testnet | On-chain audit anchoring and verification |
| **Storage** | Pinata IPFS | Decentralized PDF report storage |
| **Charts** | Recharts | Risk gauges and trend visualizations |
| **Editor** | Monaco Editor | VS Code-based Rust code editor |
| **Styling** | Tailwind CSS 3.4 | Utility-first CSS framework |

---

## Prerequisites

Before running ShieldChain locally, ensure you have the following installed:

- **Node.js** 18+ ([Download](https://nodejs.org/))
- **Python** 3.10+ ([Download](https://www.python.org/downloads/))
- **Rust** 1.91+ ([Install via rustup](https://rustup.rs/))
- **Stellar CLI** ([Installation Guide](https://developers.stellar.org/docs/tools/developer-tools))

### Required API Keys

You will need to obtain the following API keys and configure them in a `.env` file at the project root:

```env
# Groq AI API
GROQ_API_KEY=your_groq_api_key_here

# Pinata IPFS
PINATA_API_KEY=your_pinata_api_key_here
PINATA_SECRET_KEY=your_pinata_secret_key_here

# Stellar Configuration
STELLAR_SECRET_KEY=your_stellar_secret_key_here
STELLAR_PUBLIC_KEY=your_stellar_public_key_here
STELLAR_RPC_URL=https://soroban-testnet.stellar.org
SOROBAN_CONTRACT_ID=your_deployed_contract_id_here
SOROBAN_NETWORK_PASSPHRASE=Test SDF Network ; September 2015
```

**Where to get API keys:**
- **Groq**: Sign up at [console.groq.com](https://console.groq.com/)
- **Pinata**: Sign up at [pinata.cloud](https://www.pinata.cloud/)
- **Stellar**: Generate keypair using `stellar keys generate --global your-key-name --network testnet`

---

## Local Setup

### 1. Backend Setup

Navigate to the backend directory and set up a Python virtual environment:

```bash
cd backend
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the FastAPI server
uvicorn app.main:app --reload
```

The backend API will be available at `http://localhost:8000`.

### 2. Frontend Setup

Navigate to the frontend directory and install dependencies:

```bash
cd frontend
npm install

# Start the React development server
npm start
```

The frontend will be available at `http://localhost:3000`.

### 3. Smart Contract Setup

Navigate to the contract directory and build the Soroban contract:

```bash
cd contracts/audit-registry

# Build the contract for WebAssembly target
cargo build --target wasm32-unknown-unknown --release

# Deploy to Stellar Testnet
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/audit_registry.wasm \
  --source your-key-name \
  --network testnet

# Copy the returned contract ID to your .env file as SOROBAN_CONTRACT_ID
```

---

## API Reference

### POST `/analyze/`

Analyze a Soroban smart contract for security vulnerabilities.

**Request:**
```json
{
  "contract_code": "string (max 50,000 chars)",
  "contract_name": "string (optional, default 'Unknown Contract')"
}
```

**Response (200):**
```json
{
  "analysis": {
    "risk_score": 0-100,
    "vulnerabilities": [
      {
        "title": "string",
        "severity": "CRITICAL|HIGH|MEDIUM|LOW",
        "description": "string",
        "line": number,
        "fix": "string"
      }
    ],
    "exploit_story": "string",
    "score_breakdown": {
      "reasoning": "string",
      "positives": ["string"],
      "critical_count": number,
      "high_count": number,
      "medium_count": number,
      "low_count": number
    },
    "improvement_priority": [
      {
        "order": number,
        "fix": "string",
        "effort": "Low|Medium|High",
        "severity": "string"
      }
    ]
  },
  "pdf_url": "https://gateway.pinata.cloud/ipfs/{cid}",
  "cid": "string",
  "report_id": "string (timestamp)",
  "contract_hash": "string (hex SHA-256)"
}
```

**Errors:**
- `400` — Empty or oversized contract_code
- `500` — Groq API failure, PDF generation failure, or IPFS upload failure

---

### POST `/report/generate`

Generate a PDF audit report and upload to IPFS.

**Request:**
```json
{
  "analysis": {
    "risk_score": 0-100,
    "vulnerabilities": [...],
    "exploit_story": "string",
    "score_breakdown": {...},
    "improvement_priority": [...]
  },
  "contract_name": "string (optional)"
}
```

**Response (200):**
```json
{
  "cid": "string",
  "pdf_url": "https://gateway.pinata.cloud/ipfs/{cid}",
  "report_id": "string (timestamp)",
  "download_url": "/report/download/{report_id}"
}
```

**Errors:**
- `422` — Invalid analysis data (Pydantic validation)
- `502` — Pinata upload failure

---

### GET `/report/download/{report_id}`

Download a generated PDF audit report.

**Response (200):**
- Content-Type: `application/pdf`
- Content-Disposition: `attachment; filename="shieldchain_audit_{report_id}.pdf"`
- Body: PDF bytes

**Errors:**
- `404` — Report file not found

---

### POST `/blockchain/anchor`

Anchor an audit record to the Stellar blockchain.

**Request:**
```json
{
  "contract_hash": "string (hex SHA-256)",
  "report_hash": "string (hex SHA-256)",
  "risk_score": 0-100,
  "ipfs_cid": "string",
  "contract_name": "string (optional)"
}
```

**Response (200):**
```json
{
  "tx_hash": "string (64-char hex or demo_ prefix)",
  "explorer_url": "https://stellar.expert/explorer/testnet/tx/{tx_hash}",
  "contract_address": "string (SOROBAN_CONTRACT_ID from env)",
  "timestamp": "ISO-8601 string",
  "source": "stellar | local-fallback"
}
```

**Errors:**
- `409` — Contract already anchored (duplicate contract_hash)
- `502` — Soroban invocation failed AND fallback also failed (rare)

---

### GET `/blockchain/verify/{contract_hash}`

Verify an audit record on the blockchain.

**Response (200):**
```json
{
  "contract_hash": "string",
  "report_hash": "string",
  "risk_score": 0-100,
  "ipfs_cid": "string",
  "timestamp": "ISO-8601 string",
  "auditor": "string (Stellar address or 'local-dev')",
  "source": "stellar | local-store"
}
```

**Errors:**
- `404` — Audit record not found (neither on-chain nor in local store)

---

### GET `/blockchain/history/{contract_hash}`

Retrieve audit history for a contract.

**Response (200):**
```json
[
  {
    "contract_hash": "string",
    "report_hash": "string",
    "risk_score": 0-100,
    "ipfs_cid": "string | null",
    "auditor": "string",
    "created_at": "ISO-8601 string",
    "source": "stellar | local-store"
  }
]
```

Sorted by `created_at` descending. Returns empty array if no records exist.

---

### GET `/status`

Check API and service connectivity status.

**Response (200):**
```json
{
  "api_status": "ok",
  "version": "1.0.0",
  "endpoints": ["/analyze/", "/report/generate", "/blockchain/anchor", ...],
  "groq_connected": true | false,
  "stellar_connected": true | false,
  "pinata_connected": true | false
}
```

Connection flags are based on presence of environment variables.

---

## AuditRegistry Contract

The AuditRegistry Soroban smart contract provides the following public functions:

### `record_audit`

Record a new audit on the blockchain.

```rust
pub fn record_audit(
    env: Env,
    contract_hash: BytesN<32>,  // SHA-256 of contract source
    report_hash: BytesN<32>,    // SHA-256 of PDF bytes
    risk_score: u32,            // 0-100 inclusive
    ipfs_cid: String,           // Pinata CID, non-empty
)
```

**Behavior:**
- Stores an immutable `AuditRecord` keyed by `contract_hash`
- Emits an `AuditRecordedEvent` with all audit details
- Increments the total audit counter
- Requires authorization via `require_auth()`

**Errors:**
- `Error::InvalidRiskScore` (code 1) — risk_score > 100
- `Error::EmptyIpfsCid` (code 2) — ipfs_cid is empty
- `Error::AuditAlreadyExists` (code 3) — contract_hash already audited

---

### `get_audit`

Retrieve an audit record by contract hash.

```rust
pub fn get_audit(
    env: Env,
    contract_hash: BytesN<32>
) -> AuditRecord
```

**Returns:** Complete `AuditRecord` containing contract_hash, report_hash, risk_score, ipfs_cid, timestamp, and auditor address.

**Errors:**
- `Error::AuditNotFound` (code 4) — no audit exists for this contract_hash

---

### `has_been_audited`

Check if a contract has been audited.

```rust
pub fn has_been_audited(
    env: Env,
    contract_hash: BytesN<32>
) -> bool
```

**Returns:** `true` if an audit record exists, `false` otherwise.

---

### `get_total_audits`

Get the total number of audits stored.

```rust
pub fn get_total_audits(env: Env) -> u64
```

**Returns:** Total count of unique audit records stored in the contract.

**Errors:**
- `Error::ArithmeticOverflow` (code 5) — counter would overflow u64 (theoretical limit)

---

## Roadmap

### ShieldChain Sentinel — Post-Deployment Runtime Monitor

**Vision:** Continuous security monitoring for audited Soroban contracts on Stellar.

ShieldChain Sentinel is the next evolution of the platform, designed to provide real-time security monitoring for smart contracts after deployment. By streaming Stellar Horizon transactions and applying AI-powered intent classification, Sentinel will alert developers to suspicious activity on their audited contracts.

**Planned Features:**

1. **Boundary Check Layer**
   - Validates transaction parameters against audit baseline
   - Detects out-of-bounds values and unexpected function calls
   - Alerts on parameter patterns that deviate from normal usage

2. **Frequency Anomaly Detection**
   - Monitors call patterns and transaction frequency
   - Establishes historical baselines for each audited contract
   - Flags unusual spikes or patterns that may indicate exploitation attempts

3. **AI Intent Classification**
   - Uses LLaMA 3.3 70B to classify transaction intent as safe, suspicious, or critical
   - Analyzes transaction context, caller history, and parameter combinations
   - Provides natural language explanations of detected threats

4. **Real-Time Alerting**
   - Webhook notifications for critical events
   - Dashboard with live transaction feed
   - Risk score updates based on runtime behavior

**Status:** Concept phase — demonstrated in the `/sentinel` page with mock data. Full implementation planned for Phase 2.

---

## License

MIT License

Copyright (c) 2025 ShieldChain

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## Acknowledgments


**Technologies:**
- [Stellar](https://stellar.org/) — Blockchain platform
- [Soroban](https://soroban.stellar.org/) — Smart contract platform
- [Groq](https://groq.com/) — AI inference
- [Pinata](https://www.pinata.cloud/) — IPFS pinning service
- [FastAPI](https://fastapi.tiangolo.com/) — Python web framework
- [React](https://react.dev/) — Frontend framework
- [Tailwind CSS](https://tailwindcss.com/) — Styling framework
