"""
Property-based tests for PDF report generation.

Feature: shieldchain-full-stack
Property 7: Generated PDF bytes are non-empty for any valid analysis input

**Validates: Requirements 2.1, 2.2**
"""

from pathlib import Path
from typing import Any, Dict, List
import tempfile
import os

from hypothesis import given, settings, strategies as st

from app.services.report_generator import generate_audit_report


# Strategy for generating valid vulnerability dictionaries
vulnerability_strategy = st.fixed_dictionaries({
    "title": st.text(alphabet=st.characters(blacklist_categories=('Cs', 'Cc')), min_size=1, max_size=50),
    "severity": st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    "description": st.text(alphabet=st.characters(blacklist_categories=('Cs', 'Cc')), min_size=0, max_size=200),
    "line": st.integers(min_value=0, max_value=10000),
    "fix": st.text(alphabet=st.characters(blacklist_categories=('Cs', 'Cc')), min_size=0, max_size=200),
})

# Strategy for generating valid score breakdown dictionaries
score_breakdown_strategy = st.fixed_dictionaries({
    "reasoning": st.text(alphabet=st.characters(blacklist_categories=('Cs', 'Cc')), min_size=0, max_size=500),
    "positives": st.lists(st.text(alphabet=st.characters(blacklist_categories=('Cs', 'Cc')), min_size=1, max_size=100), min_size=0, max_size=5),
    "critical_count": st.integers(min_value=0, max_value=100),
    "high_count": st.integers(min_value=0, max_value=100),
    "medium_count": st.integers(min_value=0, max_value=100),
    "low_count": st.integers(min_value=0, max_value=100),
})

# Strategy for generating valid improvement priority dictionaries
improvement_priority_strategy = st.fixed_dictionaries({
    "order": st.integers(min_value=1, max_value=100),
    "fix": st.text(alphabet=st.characters(blacklist_categories=('Cs', 'Cc')), min_size=1, max_size=200),
    "effort": st.sampled_from(["Low", "Medium", "High"]),
    "severity": st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
})

# Strategy for generating valid analysis responses
analysis_response_strategy = st.fixed_dictionaries({
    "risk_score": st.integers(min_value=0, max_value=100),
    "vulnerabilities": st.lists(vulnerability_strategy, min_size=0, max_size=5),
    "exploit_story": st.text(alphabet=st.characters(blacklist_categories=('Cs', 'Cc')), min_size=0, max_size=500),
    "score_breakdown": st.one_of(st.none(), score_breakdown_strategy),
    "improvement_priority": st.one_of(
        st.none(),
        st.lists(improvement_priority_strategy, min_size=0, max_size=5)
    ),
})


@settings(max_examples=10, deadline=None)
@given(
    analysis=analysis_response_strategy,
    contract_name=st.text(alphabet=st.characters(blacklist_categories=('Cs', 'Cc')), min_size=1, max_size=100),
)
def test_property_pdf_validity(analysis: Dict[str, Any], contract_name: str):
    """
    Property 7: Generated PDF bytes are non-empty for any valid analysis input
    
    For any valid AnalyzeResponse (any risk_score in [0, 100], any list of 
    vulnerabilities including empty, any exploit_story string), generate_audit_report 
    SHALL produce a file at the returned path whose byte size is greater than zero 
    and whose first four bytes are %PDF (valid PDF magic bytes).
    
    **Validates: Requirements 2.1, 2.2**
    """
    # Create a temporary directory for this test
    with tempfile.TemporaryDirectory() as temp_dir:
        # Generate the PDF report
        pdf_path, report_id = generate_audit_report(
            analysis_response=analysis,
            contract_name=contract_name,
            output_dir=temp_dir
        )
        
        # Assert: PDF file exists at returned path
        assert os.path.exists(pdf_path), f"PDF file not found at {pdf_path}"
        
        # Assert: report_id is non-empty string
        assert isinstance(report_id, str), "report_id must be a string"
        assert len(report_id) > 0, "report_id must be non-empty"
        
        # Assert: report_id matches the timestamp format (YYYYMMDD_HHMMSS)
        assert len(report_id) == 15, f"report_id should be 15 chars (YYYYMMDD_HHMMSS), got {len(report_id)}"
        assert report_id[8] == "_", "report_id should have underscore at position 8"
        
        # Assert: filename contains report_id
        filename = Path(pdf_path).name
        assert report_id in filename, f"report_id {report_id} not found in filename {filename}"
        
        # Read the PDF file
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        
        # Assert: PDF file is non-empty
        assert len(pdf_bytes) > 0, "PDF file must be non-empty"
        
        # Assert: First four bytes are %PDF (PDF magic bytes)
        assert pdf_bytes[:4] == b"%PDF", f"PDF magic bytes not found, got {pdf_bytes[:4]}"
        
        # Additional validation: PDF should have reasonable minimum size
        # A minimal valid PDF is typically at least 100 bytes
        assert len(pdf_bytes) >= 100, f"PDF file too small ({len(pdf_bytes)} bytes), likely invalid"


@settings(max_examples=10, deadline=None)
@given(
    risk_score=st.integers(min_value=0, max_value=100),
)
def test_property_pdf_validity_minimal(risk_score: int):
    """
    Property 7 (minimal variant): Test with minimal valid analysis
    
    Even with minimal analysis data (just risk_score, empty vulnerabilities, 
    empty exploit_story), the PDF should still be valid.
    """
    minimal_analysis = {
        "risk_score": risk_score,
        "vulnerabilities": [],
        "exploit_story": "",
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        pdf_path, report_id = generate_audit_report(
            analysis_response=minimal_analysis,
            contract_name="Test Contract",
            output_dir=temp_dir
        )
        
        assert os.path.exists(pdf_path)
        
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        
        assert len(pdf_bytes) > 0
        assert pdf_bytes[:4] == b"%PDF"


if __name__ == "__main__":
    # Run a quick smoke test
    print("Running smoke test for PDF generation property...")
    
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
    
    with tempfile.TemporaryDirectory() as temp_dir:
        pdf_path, report_id = generate_audit_report(
            analysis_response=test_analysis,
            contract_name="Smoke Test Contract",
            output_dir=temp_dir
        )
        
        print(f"✓ PDF generated at: {pdf_path}")
        print(f"✓ Report ID: {report_id}")
        
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        
        print(f"✓ PDF size: {len(pdf_bytes)} bytes")
        print(f"✓ PDF magic bytes: {pdf_bytes[:4]}")
        print("\nSmoke test passed! ✓")
