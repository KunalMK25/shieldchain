"""
Property-based tests for report router endpoints.

Feature: shieldchain-full-stack
Property 8: report_id in download URL matches saved filename

**Validates: Requirements 2.6, 2.8**
"""

from pathlib import Path
from typing import Any, Dict, List
import tempfile
import os
import sys

from hypothesis import given, settings, strategies as st
from fastapi.testclient import TestClient

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).parent))

from app.main import app
from app.services.report_generator import generate_audit_report


# Strategy for generating valid vulnerability dictionaries
vulnerability_strategy = st.fixed_dictionaries({
    "title": st.text(min_size=1, max_size=100),
    "severity": st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    "description": st.text(min_size=0, max_size=500),
    "line": st.integers(min_value=0, max_value=10000),
    "fix": st.text(min_size=0, max_size=500),
})

# Strategy for generating valid score breakdown dictionaries
score_breakdown_strategy = st.fixed_dictionaries({
    "reasoning": st.text(min_size=0, max_size=1000),
    "positives": st.lists(st.text(min_size=1, max_size=200), min_size=0, max_size=10),
    "critical_count": st.integers(min_value=0, max_value=100),
    "high_count": st.integers(min_value=0, max_value=100),
    "medium_count": st.integers(min_value=0, max_value=100),
    "low_count": st.integers(min_value=0, max_value=100),
})

# Strategy for generating valid improvement priority dictionaries
improvement_priority_strategy = st.fixed_dictionaries({
    "order": st.integers(min_value=1, max_value=100),
    "fix": st.text(min_size=1, max_size=500),
    "effort": st.sampled_from(["Low", "Medium", "High"]),
    "severity": st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
})

# Strategy for generating valid analysis responses
analysis_response_strategy = st.fixed_dictionaries({
    "risk_score": st.integers(min_value=0, max_value=100),
    "vulnerabilities": st.lists(vulnerability_strategy, min_size=0, max_size=20),
    "exploit_story": st.text(min_size=0, max_size=2000),
    "score_breakdown": st.one_of(st.none(), score_breakdown_strategy),
    "improvement_priority": st.one_of(
        st.none(),
        st.lists(improvement_priority_strategy, min_size=0, max_size=10)
    ),
})


client = TestClient(app)


@settings(max_examples=50, deadline=None)
@given(
    analysis=analysis_response_strategy,
    contract_name=st.text(min_size=1, max_size=200),
)
def test_property_report_id_filename_consistency(analysis: Dict[str, Any], contract_name: str):
    """
    Property 8: report_id in download URL matches saved filename
    
    For any valid analysis input, when POST /report/generate is called:
    1. The report_id in the response SHALL match the timestamp portion of the filename
    2. The filename in backend/reports/ SHALL be shieldchain_audit_{report_id}.pdf
    3. GET /report/download/{report_id} SHALL return 200 with Content-Type: application/pdf
    
    **Validates: Requirements 2.6, 2.8**
    """
    # Mock the IPFS upload to avoid external API calls
    # We'll use a monkey patch approach
    import app.routers.report as report_module
    
    original_upload = report_module.upload_pdf_to_ipfs
    
    def mock_upload(pdf_path: str) -> Dict[str, str]:
        # Return a mock IPFS response
        return {
            "cid": "QmMockCID123456789",
            "url": "https://gateway.pinata.cloud/ipfs/QmMockCID123456789"
        }
    
    # Apply the mock
    report_module.upload_pdf_to_ipfs = mock_upload
    
    try:
        # Step 1: Call POST /report/generate
        response = client.post(
            "/report/generate",
            json={
                "analysis": analysis,
                "contract_name": contract_name
            }
        )
        
        # Assert: Response is successful
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        response_data = response.json()
        
        # Assert: Response contains required fields
        assert "report_id" in response_data, "Response missing report_id"
        assert "download_url" in response_data, "Response missing download_url"
        assert "cid" in response_data, "Response missing cid"
        assert "pdf_url" in response_data, "Response missing pdf_url"
        
        report_id = response_data["report_id"]
        download_url = response_data["download_url"]
        
        # Assert: report_id is non-empty string
        assert isinstance(report_id, str), "report_id must be a string"
        assert len(report_id) > 0, "report_id must be non-empty"
        
        # Assert: report_id matches timestamp format (YYYYMMDD_HHMMSS)
        assert len(report_id) == 15, f"report_id should be 15 chars (YYYYMMDD_HHMMSS), got {len(report_id)}"
        assert report_id[8] == "_", "report_id should have underscore at position 8"
        
        # Assert: download_url contains report_id
        expected_download_url = f"/report/download/{report_id}"
        assert download_url == expected_download_url, \
            f"download_url should be {expected_download_url}, got {download_url}"
        
        # Step 2: Verify the file exists with correct filename
        reports_dir = Path(__file__).parent / "reports"
        expected_filename = f"shieldchain_audit_{report_id}.pdf"
        expected_path = reports_dir / expected_filename
        
        assert expected_path.exists(), f"PDF file not found at {expected_path}"
        assert expected_path.is_file(), f"Path exists but is not a file: {expected_path}"
        
        # Step 3: Call GET /report/download/{report_id}
        download_response = client.get(f"/report/download/{report_id}")
        
        # Assert: Download returns 200
        assert download_response.status_code == 200, \
            f"Expected 200 for download, got {download_response.status_code}"
        
        # Assert: Content-Type is application/pdf
        content_type = download_response.headers.get("content-type", "")
        assert "application/pdf" in content_type.lower(), \
            f"Expected Content-Type to contain 'application/pdf', got {content_type}"
        
        # Assert: Response body is non-empty
        assert len(download_response.content) > 0, "Downloaded PDF is empty"
        
        # Assert: Response body starts with PDF magic bytes
        assert download_response.content[:4] == b"%PDF", \
            f"Downloaded file is not a valid PDF, magic bytes: {download_response.content[:4]}"
        
        # Cleanup: Remove the generated PDF file
        if expected_path.exists():
            expected_path.unlink()
    
    finally:
        # Restore the original upload function
        report_module.upload_pdf_to_ipfs = original_upload


@settings(max_examples=20, deadline=None)
@given(
    risk_score=st.integers(min_value=0, max_value=100),
)
def test_property_report_id_filename_consistency_minimal(risk_score: int):
    """
    Property 8 (minimal variant): Test with minimal valid analysis
    
    Even with minimal analysis data, the report_id/filename consistency should hold.
    """
    minimal_analysis = {
        "risk_score": risk_score,
        "vulnerabilities": [],
        "exploit_story": "",
    }
    
    # Mock the IPFS upload
    import app.routers.report as report_module
    
    original_upload = report_module.upload_pdf_to_ipfs
    
    def mock_upload(pdf_path: str) -> Dict[str, str]:
        return {
            "cid": "QmMockCIDMinimal",
            "url": "https://gateway.pinata.cloud/ipfs/QmMockCIDMinimal"
        }
    
    report_module.upload_pdf_to_ipfs = mock_upload
    
    try:
        response = client.post(
            "/report/generate",
            json={
                "analysis": minimal_analysis,
                "contract_name": "Minimal Test Contract"
            }
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        report_id = response_data["report_id"]
        
        # Verify file exists
        reports_dir = Path(__file__).parent / "reports"
        expected_path = reports_dir / f"shieldchain_audit_{report_id}.pdf"
        assert expected_path.exists()
        
        # Verify download works
        download_response = client.get(f"/report/download/{report_id}")
        assert download_response.status_code == 200
        assert "application/pdf" in download_response.headers.get("content-type", "").lower()
        
        # Cleanup
        if expected_path.exists():
            expected_path.unlink()
    
    finally:
        report_module.upload_pdf_to_ipfs = original_upload


def test_download_nonexistent_report():
    """
    Test that downloading a non-existent report returns 404.
    
    This is not a property test but validates the error handling.
    """
    response = client.get("/report/download/nonexistent_report_id")
    assert response.status_code == 404
    assert "detail" in response.json()


if __name__ == "__main__":
    # Run a quick smoke test
    print("Running smoke test for report router property...")
    
    test_analysis = {
        "risk_score": 75,
        "vulnerabilities": [
            {
                "title": "Test Vulnerability",
                "severity": "HIGH",
                "description": "This is a test",
                "line": 42,
                "fix": "Fix it",
            }
        ],
        "exploit_story": "Test exploit story",
        "score_breakdown": {
            "reasoning": "Test reasoning",
            "positives": ["Good auth"],
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
        },
        "improvement_priority": [
            {
                "order": 1,
                "fix": "Fix the vulnerability",
                "effort": "Low",
                "severity": "HIGH",
            }
        ],
    }
    
    # Mock IPFS upload
    import app.routers.report as report_module
    
    original_upload = report_module.upload_pdf_to_ipfs
    
    def mock_upload(pdf_path: str) -> Dict[str, str]:
        return {
            "cid": "QmSmokeTestCID",
            "url": "https://gateway.pinata.cloud/ipfs/QmSmokeTestCID"
        }
    
    report_module.upload_pdf_to_ipfs = mock_upload
    
    try:
        response = client.post(
            "/report/generate",
            json={
                "analysis": test_analysis,
                "contract_name": "Smoke Test Contract"
            }
        )
        
        print(f"✓ POST /report/generate status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Response data: {data}")
            
            report_id = data["report_id"]
            print(f"✓ Report ID: {report_id}")
            
            # Test download
            download_response = client.get(f"/report/download/{report_id}")
            print(f"✓ GET /report/download/{report_id} status: {download_response.status_code}")
            print(f"✓ Content-Type: {download_response.headers.get('content-type')}")
            print(f"✓ Content size: {len(download_response.content)} bytes")
            
            # Cleanup
            reports_dir = Path(__file__).parent / "reports"
            pdf_path = reports_dir / f"shieldchain_audit_{report_id}.pdf"
            if pdf_path.exists():
                pdf_path.unlink()
                print(f"✓ Cleaned up test file")
            
            print("\nSmoke test passed! ✓")
        else:
            print(f"✗ Smoke test failed with status {response.status_code}")
            print(f"Response: {response.text}")
    
    finally:
        report_module.upload_pdf_to_ipfs = original_upload
