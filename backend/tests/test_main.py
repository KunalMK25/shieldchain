"""
Unit tests for main application and status endpoint.

Tests connectivity status checks based on environment variables.

**Validates: Requirements 4.3, 4.4, 4.5, 4.6**
"""

from pathlib import Path
import sys
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app


client = TestClient(app)


def test_status_missing_groq_key():
    """
    Test that when GROQ_API_KEY is unset, groq_connected=false.
    
    **Validates: Requirement 4.4**
    """
    # Mock environment to unset GROQ_API_KEY
    with patch.dict(os.environ, {}, clear=False):
        # Remove GROQ_API_KEY if it exists
        if 'GROQ_API_KEY' in os.environ:
            del os.environ['GROQ_API_KEY']
        
        response = client.get("/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "groq_connected" in data
        assert data["groq_connected"] is False


def test_status_missing_stellar_keys():
    """
    Test that when Stellar env vars are unset, stellar_connected=false.
    
    **Validates: Requirement 4.6**
    """
    # Mock environment to unset Stellar keys
    with patch.dict(os.environ, {}, clear=False):
        # Remove Stellar env vars if they exist
        stellar_keys = ['STELLAR_RPC_URL', 'STELLAR_SECRET_KEY', 'STELLAR_PUBLIC_KEY']
        for key in stellar_keys:
            if key in os.environ:
                del os.environ[key]
        
        response = client.get("/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "stellar_connected" in data
        assert data["stellar_connected"] is False


def test_status_missing_pinata_keys():
    """
    Test that when Pinata env vars are unset, pinata_connected=false.
    
    **Validates: Requirement 4.5**
    """
    # Mock environment to unset Pinata keys
    with patch.dict(os.environ, {}, clear=False):
        # Remove Pinata env vars if they exist
        pinata_keys = ['PINATA_API_KEY', 'PINATA_SECRET_KEY']
        for key in pinata_keys:
            if key in os.environ:
                del os.environ[key]
        
        response = client.get("/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "pinata_connected" in data
        assert data["pinata_connected"] is False


def test_status_all_connected():
    """
    Test that when all env vars are set, all connections are true.
    
    This is a positive test to verify the status endpoint works correctly.
    """
    # Mock environment with all required keys
    mock_env = {
        'GROQ_API_KEY': 'test_groq_key',
        'STELLAR_RPC_URL': 'https://soroban-testnet.stellar.org',
        'STELLAR_SECRET_KEY': 'SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
        'PINATA_API_KEY': 'test_pinata_key',
        'PINATA_SECRET_KEY': 'test_pinata_secret'
    }
    
    with patch.dict(os.environ, mock_env, clear=False):
        response = client.get("/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["groq_connected"] is True
        assert data["stellar_connected"] is True
        assert data["pinata_connected"] is True


def test_status_response_structure():
    """
    Test that /status returns all required fields.
    
    **Validates: Requirement 4.3**
    """
    response = client.get("/status")
    
    assert response.status_code == 200
    data = response.json()
    
    # Verify all required fields are present
    assert "api_status" in data
    assert "version" in data
    assert "endpoints" in data
    assert "groq_connected" in data
    assert "stellar_connected" in data
    assert "pinata_connected" in data
    assert "dynamic_analysis_enabled" in data
    
    # Verify field types
    assert isinstance(data["api_status"], str)
    assert isinstance(data["version"], str)
    assert isinstance(data["endpoints"], list)
    assert isinstance(data["groq_connected"], bool)
    assert isinstance(data["stellar_connected"], bool)
    assert isinstance(data["pinata_connected"], bool)
    assert isinstance(data["dynamic_analysis_enabled"], bool)
    
    # Verify api_status value
    assert data["api_status"] == "ok"
    
    # Verify endpoints list is non-empty
    assert len(data["endpoints"]) > 0


def test_status_partial_stellar_keys():
    """
    Test that stellar_connected requires BOTH RPC_URL and SECRET_KEY.
    
    If only one is present, stellar_connected should be false.
    """
    # Test with only RPC_URL
    with patch.dict(os.environ, {'STELLAR_RPC_URL': 'https://test.stellar.org'}, clear=False):
        if 'STELLAR_SECRET_KEY' in os.environ:
            del os.environ['STELLAR_SECRET_KEY']
        
        response = client.get("/status")
        data = response.json()
        
        assert data["stellar_connected"] is False
    
    # Test with only SECRET_KEY
    with patch.dict(os.environ, {'STELLAR_SECRET_KEY': 'STEST'}, clear=False):
        if 'STELLAR_RPC_URL' in os.environ:
            del os.environ['STELLAR_RPC_URL']
        
        response = client.get("/status")
        data = response.json()
        
        assert data["stellar_connected"] is False


def test_status_partial_pinata_keys():
    """
    Test that pinata_connected requires BOTH API_KEY and SECRET_KEY.
    
    If only one is present, pinata_connected should be false.
    """
    # Test with only API_KEY
    with patch.dict(os.environ, {'PINATA_API_KEY': 'test_key'}, clear=False):
        if 'PINATA_SECRET_KEY' in os.environ:
            del os.environ['PINATA_SECRET_KEY']
        
        response = client.get("/status")
        data = response.json()
        
        assert data["pinata_connected"] is False
    
    # Test with only SECRET_KEY
    with patch.dict(os.environ, {'PINATA_SECRET_KEY': 'test_secret'}, clear=False):
        if 'PINATA_API_KEY' in os.environ:
            del os.environ['PINATA_API_KEY']
        
        response = client.get("/status")
        data = response.json()
        
        assert data["pinata_connected"] is False


def test_status_dynamic_analysis_enabled():
    """
    Test that dynamic_analysis_enabled is true when both STELLAR_PUBLIC_KEY and STELLAR_SECRET_KEY are set.
    
    **Validates: Requirement 12.6**
    """
    # Test with both keys present
    mock_env = {
        'STELLAR_PUBLIC_KEY': 'GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
        'STELLAR_SECRET_KEY': 'SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
    }
    
    with patch.dict(os.environ, mock_env, clear=False):
        response = client.get("/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "dynamic_analysis_enabled" in data
        assert data["dynamic_analysis_enabled"] is True


def test_status_dynamic_analysis_disabled_missing_keys():
    """
    Test that dynamic_analysis_enabled is false when STELLAR keys are missing.
    
    **Validates: Requirement 12.6**
    """
    # Test with both keys missing
    with patch.dict(os.environ, {}, clear=False):
        stellar_keys = ['STELLAR_PUBLIC_KEY', 'STELLAR_SECRET_KEY']
        for key in stellar_keys:
            if key in os.environ:
                del os.environ[key]
        
        response = client.get("/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "dynamic_analysis_enabled" in data
        assert data["dynamic_analysis_enabled"] is False


def test_status_dynamic_analysis_disabled_partial_keys():
    """
    Test that dynamic_analysis_enabled requires BOTH STELLAR_PUBLIC_KEY and STELLAR_SECRET_KEY.
    
    **Validates: Requirement 12.6**
    """
    # Test with only PUBLIC_KEY
    with patch.dict(os.environ, {'STELLAR_PUBLIC_KEY': 'GTEST'}, clear=False):
        if 'STELLAR_SECRET_KEY' in os.environ:
            del os.environ['STELLAR_SECRET_KEY']
        
        response = client.get("/status")
        data = response.json()
        
        assert data["dynamic_analysis_enabled"] is False
    
    # Test with only SECRET_KEY
    with patch.dict(os.environ, {'STELLAR_SECRET_KEY': 'STEST'}, clear=False):
        if 'STELLAR_PUBLIC_KEY' in os.environ:
            del os.environ['STELLAR_PUBLIC_KEY']
        
        response = client.get("/status")
        data = response.json()
        
        assert data["dynamic_analysis_enabled"] is False


def test_root_endpoint():
    """
    Test that the root endpoint returns a valid response.
    
    This is a basic sanity check for the application.
    """
    response = client.get("/")
    
    assert response.status_code == 200
    data = response.json()
    
    assert "message" in data
    assert "version" in data
    assert "status" in data


def test_health_endpoint():
    """
    Test that the health endpoint returns ok status.
    
    This is a basic sanity check for the application.
    """
    response = client.get("/health")
    
    assert response.status_code == 200
    data = response.json()
    
    assert "status" in data
    assert data["status"] == "ok"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
