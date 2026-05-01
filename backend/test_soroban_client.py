"""
Unit tests for soroban_client.py functions.
"""
import os
import subprocess
from unittest.mock import patch, MagicMock
import pytest
from dotenv import load_dotenv

# Load environment variables
load_dotenv('../.env')

# Import the function to test
from app.services.soroban_client import get_audit_from_soroban


class TestGetAuditFromSoroban:
    """Test suite for get_audit_from_soroban function."""

    @patch.dict(os.environ, {
        'SOROBAN_CONTRACT_ID': 'test_contract_id',
        'STELLAR_RPC_URL': 'https://test.stellar.org',
        'SOROBAN_NETWORK_PASSPHRASE': 'Test SDF Network ; September 2015'
    })
    @patch('app.services.soroban_client.subprocess.run')
    def test_successful_audit_retrieval(self, mock_run):
        """Test successful retrieval of audit data."""
        # Mock successful CLI response
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_result.stdout = """
        AuditRecord {
            contract_hash: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
            report_hash: fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321,
            risk_score: 42,
            ipfs_cid: "QmTest123456789",
            timestamp: 1704067200,
            auditor: GAIAXYZ123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789ABC
        }
        """
        mock_run.return_value = mock_result

        # Call the function
        result = get_audit_from_soroban("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

        # Verify the result
        assert result['contract_hash'] == "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        assert result['report_hash'] == "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
        assert result['risk_score'] == 42
        assert result['ipfs_cid'] == "QmTest123456789"
        assert result['timestamp'] == 1704067200
        assert result['auditor'] == "GAIAXYZ123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789ABC"

    @patch.dict(os.environ, {
        'SOROBAN_CONTRACT_ID': 'test_contract_id',
        'STELLAR_RPC_URL': 'https://test.stellar.org',
        'SOROBAN_NETWORK_PASSPHRASE': 'Test SDF Network ; September 2015'
    })
    @patch('app.services.soroban_client.subprocess.run')
    def test_audit_not_found(self, mock_run):
        """Test handling of AuditNotFound error."""
        # Mock CLI response with AuditNotFound error
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Error: AuditNotFound"
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        # Call the function and expect RuntimeError
        with pytest.raises(RuntimeError, match="AuditNotFound"):
            get_audit_from_soroban("nonexistent_hash")

    @patch.dict(os.environ, {
        'SOROBAN_CONTRACT_ID': 'test_contract_id',
        'STELLAR_RPC_URL': 'https://test.stellar.org',
        'SOROBAN_NETWORK_PASSPHRASE': 'Test SDF Network ; September 2015'
    })
    @patch('app.services.soroban_client.subprocess.run')
    def test_cli_failure(self, mock_run):
        """Test handling of CLI invocation failure."""
        # Mock CLI failure
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Connection timeout"
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        # Call the function and expect RuntimeError
        with pytest.raises(RuntimeError, match="Stellar CLI invoke failed"):
            get_audit_from_soroban("some_hash")

    @patch.dict(os.environ, {
        'SOROBAN_CONTRACT_ID': 'test_contract_id',
        'STELLAR_RPC_URL': 'https://test.stellar.org',
        'SOROBAN_NETWORK_PASSPHRASE': 'Test SDF Network ; September 2015'
    })
    @patch('app.services.soroban_client.subprocess.run')
    def test_empty_output(self, mock_run):
        """Test handling of empty CLI output."""
        # Mock empty output
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        # Call the function and expect RuntimeError
        with pytest.raises(RuntimeError, match="empty output"):
            get_audit_from_soroban("some_hash")

    @patch.dict(os.environ, {
        'SOROBAN_CONTRACT_ID': 'test_contract_id',
        'STELLAR_RPC_URL': 'https://test.stellar.org',
        'SOROBAN_NETWORK_PASSPHRASE': 'Test SDF Network ; September 2015'
    })
    @patch('app.services.soroban_client.subprocess.run')
    def test_missing_fields(self, mock_run):
        """Test handling of incomplete audit record."""
        # Mock incomplete response (missing auditor field)
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_result.stdout = """
        AuditRecord {
            contract_hash: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
            report_hash: fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321,
            risk_score: 42,
            ipfs_cid: "QmTest123456789",
            timestamp: 1704067200
        }
        """
        mock_run.return_value = mock_result

        # Call the function and expect RuntimeError
        with pytest.raises(RuntimeError, match="missing fields"):
            get_audit_from_soroban("some_hash")


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
