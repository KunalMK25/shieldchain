"""
Unit tests for GroqClassifier service.

Feature: dynamic-analysis-sentinel-audit
Tests: Groq API failure handling and prompt formatting

**Validates: Requirements 4.2, 4.7**
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json

from app.services.groq_classifier import GroqClassifier, CLASSIFICATION_PROMPT
from app.models.schemas import DynamicLogEntry


@pytest.fixture
def sample_entry():
    """Create a sample DynamicLogEntry for testing."""
    return DynamicLogEntry(
        timestamp="2025-04-30T14:23:11Z",
        transaction_hash="abc123",
        function_called="transfer",
        parameters={"amount": 1000, "to": "GTEST123"},
        result="success",
        error=None,
        anomaly=False,
        severity="NONE",
        status="NORMAL",
        reason=""
    )


@pytest.mark.asyncio
async def test_groq_unavailable_returns_normal(sample_entry):
    """
    Test that Groq API failure sets status="NORMAL" and reason="classification_unavailable"
    
    When the Groq API raises an exception, the classifier should gracefully
    handle the failure by setting safe default values rather than propagating
    the exception.
    
    **Validates: Requirements 4.7**
    """
    # Create classifier
    classifier = GroqClassifier(api_key="test_key")
    
    # Mock the Groq client to raise an exception
    with patch.object(classifier.client.chat.completions, 'create') as mock_create:
        mock_create.side_effect = Exception("Groq API unavailable")
        
        # Classify the entry
        result = await classifier.classify(sample_entry)
        
        # Assert fallback behavior
        assert result.status == "NORMAL", \
            f"Expected status='NORMAL' on Groq failure, got '{result.status}'"
        assert result.reason == "classification_unavailable", \
            f"Expected reason='classification_unavailable', got '{result.reason}'"
        assert result.anomaly is False, \
            f"Expected anomaly=False on Groq failure, got {result.anomaly}"
        assert result.severity == "NONE", \
            f"Expected severity='NONE' on Groq failure, got '{result.severity}'"


@pytest.mark.asyncio
async def test_groq_json_decode_error_returns_normal(sample_entry):
    """
    Test that invalid JSON response from Groq is handled gracefully.
    
    When Groq returns a response that cannot be parsed as JSON, the
    classifier should set safe defaults.
    
    **Validates: Requirements 4.7**
    """
    classifier = GroqClassifier(api_key="test_key")
    
    # Mock Groq to return invalid JSON
    mock_response = Mock()
    mock_response.choices = [Mock()]
    mock_response.choices[0].message.content = "This is not valid JSON"
    
    with patch.object(classifier.client.chat.completions, 'create') as mock_create:
        mock_create.return_value = mock_response
        
        result = await classifier.classify(sample_entry)
        
        # Assert fallback behavior
        assert result.status == "NORMAL"
        assert result.reason == "classification_unavailable"
        assert result.anomaly is False
        assert result.severity == "NONE"


@pytest.mark.asyncio
async def test_prompt_format(sample_entry):
    """
    Test that the classification prompt contains transaction data.
    
    The prompt sent to Groq should include the transaction's function name,
    parameters, result, error, and transaction hash.
    
    **Validates: Requirements 4.2**
    """
    classifier = GroqClassifier(api_key="test_key")
    
    # Mock successful Groq response
    mock_response = Mock()
    mock_response.choices = [Mock()]
    mock_response.choices[0].message.content = json.dumps({
        "anomaly": False,
        "severity": "NONE",
        "reason": ""
    })
    
    with patch.object(classifier.client.chat.completions, 'create') as mock_create:
        mock_create.return_value = mock_response
        
        await classifier.classify(sample_entry)
        
        # Verify the API was called
        assert mock_create.called, "Groq API should have been called"
        
        # Get the call arguments
        call_args = mock_create.call_args
        messages = call_args.kwargs['messages']
        
        # Find the user message
        user_message = None
        for msg in messages:
            if msg['role'] == 'user':
                user_message = msg['content']
                break
        
        assert user_message is not None, "User message not found in API call"
        
        # Verify transaction data is in the prompt
        assert "transfer" in user_message, \
            "Function name should be in prompt"
        assert "abc123" in user_message, \
            "Transaction hash should be in prompt"
        assert "1000" in user_message or "amount" in user_message, \
            "Parameters should be in prompt"


@pytest.mark.asyncio
async def test_classify_all_sequential(sample_entry):
    """
    Test that classify_all processes entries sequentially.
    
    All entries should be classified, and the function should never raise
    even if individual classifications fail.
    
    **Validates: Requirements 4.1**
    """
    classifier = GroqClassifier(api_key="test_key")
    
    # Create multiple entries
    entries = [
        sample_entry,
        DynamicLogEntry(
            timestamp="2025-04-30T14:23:12Z",
            transaction_hash="def456",
            function_called="mint",
            parameters={"amount": 500},
            result=None,
            error="overflow",
            anomaly=False,
            severity="NONE",
            status="NORMAL",
            reason=""
        ),
        DynamicLogEntry(
            timestamp="2025-04-30T14:23:13Z",
            transaction_hash="ghi789",
            function_called="burn",
            parameters={"amount": 200},
            result="success",
            error=None,
            anomaly=False,
            severity="NONE",
            status="NORMAL",
            reason=""
        )
    ]
    
    # Mock Groq to return different responses
    mock_responses = [
        json.dumps({"anomaly": False, "severity": "NONE", "reason": ""}),
        json.dumps({"anomaly": True, "severity": "HIGH", "reason": "Overflow detected"}),
        json.dumps({"anomaly": False, "severity": "LOW", "reason": ""}),
    ]
    
    call_count = 0
    def mock_create(*args, **kwargs):
        nonlocal call_count
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = mock_responses[call_count]
        call_count += 1
        return mock_response
    
    with patch.object(classifier.client.chat.completions, 'create', side_effect=mock_create):
        results = await classifier.classify_all(entries)
        
        # Assert all entries were processed
        assert len(results) == 3, f"Expected 3 results, got {len(results)}"
        
        # Verify classifications
        assert results[0].status == "NORMAL"
        assert results[1].status == "FLAGGED"  # HIGH + anomaly=True
        assert results[2].status == "NORMAL"


@pytest.mark.asyncio
async def test_classify_handles_markdown_json_response(sample_entry):
    """
    Test that classifier can extract JSON from markdown code blocks.
    
    Groq sometimes wraps JSON responses in markdown code blocks.
    The classifier should handle this gracefully.
    
    **Validates: Requirements 4.2**
    """
    classifier = GroqClassifier(api_key="test_key")
    
    # Mock Groq to return JSON wrapped in markdown
    mock_response = Mock()
    mock_response.choices = [Mock()]
    mock_response.choices[0].message.content = """```json
{
    "anomaly": true,
    "severity": "CRITICAL",
    "reason": "Unauthorized access detected"
}
```"""
    
    with patch.object(classifier.client.chat.completions, 'create') as mock_create:
        mock_create.return_value = mock_response
        
        result = await classifier.classify(sample_entry)
        
        # Assert the JSON was correctly extracted and parsed
        assert result.anomaly is True
        assert result.severity == "CRITICAL"
        assert result.status == "FLAGGED"
        assert result.reason == "Unauthorized access detected"


@pytest.mark.asyncio
async def test_classify_all_continues_on_individual_failure():
    """
    Test that classify_all continues processing even if some entries fail.
    
    If one entry's classification fails, the others should still be processed.
    
    **Validates: Requirements 4.1**
    """
    classifier = GroqClassifier(api_key="test_key")
    
    entries = [
        DynamicLogEntry(
            timestamp="2025-04-30T14:23:11Z",
            transaction_hash="abc123",
            function_called="transfer",
            parameters={"amount": 1000},
            result="success",
            error=None,
            anomaly=False,
            severity="NONE",
            status="NORMAL",
            reason=""
        ),
        DynamicLogEntry(
            timestamp="2025-04-30T14:23:12Z",
            transaction_hash="def456",
            function_called="mint",
            parameters={"amount": 500},
            result=None,
            error="error",
            anomaly=False,
            severity="NONE",
            status="NORMAL",
            reason=""
        )
    ]
    
    call_count = 0
    def mock_create(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call fails
            raise Exception("API error")
        else:
            # Second call succeeds
            mock_response = Mock()
            mock_response.choices = [Mock()]
            mock_response.choices[0].message.content = json.dumps({
                "anomaly": False,
                "severity": "NONE",
                "reason": ""
            })
            return mock_response
    
    with patch.object(classifier.client.chat.completions, 'create', side_effect=mock_create):
        results = await classifier.classify_all(entries)
        
        # Both entries should be returned
        assert len(results) == 2
        
        # First entry should have fallback values
        assert results[0].status == "NORMAL"
        assert results[0].reason == "classification_unavailable"
        
        # Second entry should be classified normally
        assert results[1].status == "NORMAL"
        assert results[1].reason == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
