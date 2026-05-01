"""
Groq AI anomaly classification service for dynamic analysis.

This service sends transaction results to Groq LLaMA 3.3 70B for anomaly detection
and classification, returning structured anomaly flags, severity levels, and explanations.
"""

import logging
from typing import List
from groq import Groq
import json

from app.models.schemas import DynamicLogEntry

logger = logging.getLogger(__name__)

# Classification prompt template
CLASSIFICATION_PROMPT = (
    "Given this Soroban transaction result: {tx_data}, "
    "does it indicate a vulnerability? "
    'Respond JSON: {{ "anomaly": bool, "severity": string, "reason": string }}'
)

# Status mapping: (severity, anomaly) -> status
STATUS_MAP = {
    # anomaly=True
    ("CRITICAL", True): "FLAGGED",
    ("HIGH", True): "FLAGGED",
    ("MEDIUM", True): "SUSPICIOUS",
    ("LOW", True): "SUSPICIOUS",
    # anomaly=False
    ("CRITICAL", False): "NORMAL",
    ("HIGH", False): "NORMAL",
    ("MEDIUM", False): "NORMAL",
    ("LOW", False): "NORMAL",
    ("NONE", False): "NORMAL",
}


class GroqClassifier:
    """
    Classifies transaction results using Groq LLaMA 3.3 70B.
    
    Methods:
        classify(entry): Classifies a single DynamicLogEntry
        classify_all(entries): Classifies all entries sequentially
        _determine_status(anomaly, severity): Pure function mapping to status
    """
    
    def __init__(self, api_key: str):
        """
        Initialize the Groq classifier.
        
        Args:
            api_key: Groq API key for authentication
        """
        self.client = Groq(api_key=api_key)
    
    async def classify(self, entry: DynamicLogEntry) -> DynamicLogEntry:
        """
        Classify a single transaction result.
        
        Sends the entry data to Groq for anomaly classification and updates
        the entry's anomaly, severity, status, and reason fields.
        
        On Groq API failure: sets status="NORMAL", reason="classification_unavailable"
        
        Args:
            entry: DynamicLogEntry to classify
            
        Returns:
            Updated DynamicLogEntry with classification results
        """
        try:
            # Build transaction data string for the prompt
            tx_data = {
                "function": entry.function_called,
                "parameters": entry.parameters,
                "result": entry.result,
                "error": entry.error,
                "transaction_hash": entry.transaction_hash,
            }
            tx_data_str = json.dumps(tx_data)
            
            # Format the classification prompt
            prompt = CLASSIFICATION_PROMPT.format(tx_data=tx_data_str)
            
            # Call Groq API
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security expert analyzing Soroban smart contract transactions. Respond only with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=200,
            )
            
            # Parse the response
            response_text = response.choices[0].message.content.strip()
            
            # Extract JSON from response (handle markdown code blocks)
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
            
            classification = json.loads(response_text)
            
            # Update entry fields
            entry.anomaly = classification.get("anomaly", False)
            entry.severity = classification.get("severity", "NONE").upper()
            entry.reason = classification.get("reason", "")
            entry.status = self._determine_status(entry.anomaly, entry.severity)
            
            logger.info(
                f"Classified transaction {entry.transaction_hash}: "
                f"anomaly={entry.anomaly}, severity={entry.severity}, status={entry.status}"
            )
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Groq response as JSON: {e}")
            entry.status = "NORMAL"
            entry.reason = "classification_unavailable"
            entry.anomaly = False
            entry.severity = "NONE"
            
        except Exception as e:
            logger.error(f"Groq classification failed for {entry.transaction_hash}: {e}")
            entry.status = "NORMAL"
            entry.reason = "classification_unavailable"
            entry.anomaly = False
            entry.severity = "NONE"
        
        return entry
    
    async def classify_all(self, entries: List[DynamicLogEntry]) -> List[DynamicLogEntry]:
        """
        Classify all entries sequentially.
        
        Runs classifications one at a time to avoid Groq rate limits.
        Never raises - individual failures are handled in classify().
        
        Args:
            entries: List of DynamicLogEntry objects to classify
            
        Returns:
            List of classified DynamicLogEntry objects
        """
        classified_entries = []
        for entry in entries:
            classified_entry = await self.classify(entry)
            classified_entries.append(classified_entry)
        
        return classified_entries
    
    def _determine_status(self, anomaly: bool, severity: str) -> str:
        """
        Pure function mapping (anomaly, severity) to status string.
        
        Uses STATUS_MAP:
        - anomaly=True + CRITICAL/HIGH → "FLAGGED"
        - anomaly=True + MEDIUM/LOW → "SUSPICIOUS"
        - anomaly=False + any severity → "NORMAL"
        
        Args:
            anomaly: Whether an anomaly was detected
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, NONE)
            
        Returns:
            Status string: "NORMAL", "SUSPICIOUS", or "FLAGGED"
        """
        # Normalize severity to uppercase
        severity = severity.upper()
        
        # Look up in STATUS_MAP, default to NORMAL for unknown combinations
        return STATUS_MAP.get((severity, anomaly), "NORMAL")
