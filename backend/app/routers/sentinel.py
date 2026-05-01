"""
Sentinel SSE streaming router for ShieldChain.

Exposes GET /sentinel/stream/{contract_hash} endpoint that streams
live Sentinel feed entries via Server-Sent Events.

For simulated contracts, generates realistic demo transaction data.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from app.services.sentinel import active_monitors
from app.services.sentinel_demo import SentinelDemoGenerator
import asyncio
import json
import logging
import os

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/sentinel",
    tags=["Sentinel"]
)


@router.post("/demo/start/{contract_hash}")
async def start_demo_sentinel(contract_hash: str):
    """
    Initialize a demo sentinel monitor for the Sentinel page.
    
    Creates a simulated contract monitor that will stream demo transaction data.
    This is used for demonstration purposes when no real contract is available.
    
    Args:
        contract_hash: Hash identifier for the demo contract (e.g., CSIM_DEMO_CONTRACT_001)
    
    Returns:
        Success message with contract details
    """
    from app.services.sentinel import SentinelMonitor, active_monitors
    from app.models.schemas import AuditBounds
    
    # Check if monitor already exists
    if contract_hash in active_monitors:
        logger.info(f"Demo sentinel already active for {contract_hash}")
        return {
            "status": "already_active",
            "contract_hash": contract_hash,
            "message": "Demo sentinel is already monitoring this contract"
        }
    
    # Create demo audit bounds with common functions
    demo_bounds = AuditBounds(
        max_param_value=1000000,
        expected_functions=["transfer", "mint", "burn", "approve", "withdraw", "deposit", "swap", "claim"],
        risk_score=45
    )
    
    # Create and register the monitor
    monitor = SentinelMonitor(
        contract_id=f"CSIM_{contract_hash}",  # Simulated contract ID
        contract_hash=contract_hash,
        audit_bounds=demo_bounds
    )
    
    active_monitors[contract_hash] = monitor
    
    # Start monitoring in background (non-blocking)
    import asyncio
    asyncio.create_task(monitor.start_monitoring())
    
    logger.info(f"Demo sentinel started for {contract_hash}")
    
    return {
        "status": "started",
        "contract_hash": contract_hash,
        "contract_id": f"CSIM_{contract_hash}",
        "message": "Demo sentinel monitoring started successfully"
    }


@router.get("/stream/{contract_hash}")
async def stream_sentinel(contract_hash: str) -> StreamingResponse:
    """
    Server-Sent Events endpoint for live Sentinel feed.
    
    Streams real-time transaction monitoring entries for a deployed contract.
    For simulated contracts (CSIM...), generates realistic demo data.
    
    Args:
        contract_hash: SHA-256 hash of the contract code (hex)
    
    Returns:
        StreamingResponse with text/event-stream media type
    
    Raises:
        HTTPException 404: No active SentinelMonitor for the given contract_hash
    """
    # Look up the active monitor for this contract
    monitor = active_monitors.get(contract_hash)
    
    if monitor is None:
        logger.warning(f"No active sentinel monitor found for contract {contract_hash}")
        raise HTTPException(
            status_code=404,
            detail="No active sentinel for this contract"
        )
    
    # Check if this is a simulated contract
    is_simulated = monitor.contract_id and monitor.contract_id.startswith("CSIM")
    
    if is_simulated:
        logger.info(f"Streaming DEMO data for simulated contract {contract_hash}")
        return StreamingResponse(
            content=_demo_event_generator(monitor, contract_hash),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            }
        )
    else:
        logger.info(f"Streaming REAL data for contract {contract_hash}")
        return StreamingResponse(
            content=_real_event_generator(monitor, contract_hash),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            }
        )


async def _demo_event_generator(monitor, contract_hash: str):
    """
    Generate realistic demo transaction data for simulated contracts.
    
    Creates transactions that match the contract's functions and show
    realistic monitoring patterns including normal, suspicious, and flagged transactions.
    """
    try:
        # Get expected functions from monitor
        expected_functions = monitor.audit_bounds.expected_functions
        
        # Create demo generator
        demo_gen = SentinelDemoGenerator(
            contract_code="",  # Not needed for demo
            contract_hash=contract_hash,
            vulnerabilities=[],  # Could be enhanced to pass actual vulnerabilities
            expected_functions=expected_functions
        )
        
        # Generate initial batch of transactions (looks like historical data)
        initial_transactions = demo_gen.generate_transaction_stream(count=12)
        
        logger.info(f"Generated {len(initial_transactions)} initial demo transactions")
        
        # Send initial transactions with slight delay to simulate loading
        for entry in initial_transactions:
            entry_dict = entry.model_dump()
            data_line = f"data: {json.dumps(entry_dict)}\n\n"
            yield data_line
            await asyncio.sleep(0.3)  # Stagger initial load
        
        # Check if we're in test mode
        is_test_mode = "PYTEST_CURRENT_TEST" in os.environ
        
        if is_test_mode:
            # In test mode: exit after initial batch
            await asyncio.sleep(0.1)
            return
        
        # Continue streaming new transactions (looks like live monitoring)
        tx_counter = 0
        max_additional_tx = 15  # Stream 15 more transactions
        
        while tx_counter < max_additional_tx:
            # Generate next transaction with realistic distribution
            import random
            rand = random.random()
            
            if rand < 0.65:  # 65% normal
                entry = demo_gen._generate_normal_tx()
            elif rand < 0.90:  # 25% suspicious
                entry = demo_gen._generate_suspicious_tx()
            else:  # 10% flagged
                entry = demo_gen._generate_flagged_tx()
            
            entry_dict = entry.model_dump()
            data_line = f"data: {json.dumps(entry_dict)}\n\n"
            yield data_line
            
            tx_counter += 1
            
            # Realistic delay between transactions (2-5 seconds)
            await asyncio.sleep(random.uniform(2.0, 5.0))
        
        # Send completion heartbeat
        logger.info(f"Demo stream completed for contract {contract_hash}")
        
    except GeneratorExit:
        logger.info(f"Client disconnected from demo stream for contract {contract_hash}")
    except Exception as e:
        logger.error(f"Error in demo stream: {e}", exc_info=True)
        error_data = {"error": "Stream error", "message": str(e)}
        yield f"data: {json.dumps(error_data)}\n\n"


async def _real_event_generator(monitor, contract_hash: str):
    """
    Stream real monitoring data from Horizon for actual deployed contracts.
    """
    last_seen_index = 0
    
    try:
        # First: yield any existing entries
        feed = monitor.get_live_feed()
        
        for entry in feed:
            entry_dict = entry.model_dump() if hasattr(entry, 'model_dump') else entry.dict()
            data_line = f"data: {json.dumps(entry_dict)}\n\n"
            yield data_line
            await asyncio.sleep(0)
            last_seen_index += 1
        
        # Check if we're in test mode
        is_test_mode = "PYTEST_CURRENT_TEST" in os.environ
        
        if is_test_mode:
            await asyncio.sleep(0.1)
            return
        
        # Continue streaming new entries
        while True:
            await asyncio.sleep(10)  # Poll every 10 seconds
            
            feed = monitor.get_live_feed()
            new_entries = feed[last_seen_index:]
            
            for entry in new_entries:
                entry_dict = entry.model_dump() if hasattr(entry, 'model_dump') else entry.dict()
                data_line = f"data: {json.dumps(entry_dict)}\n\n"
                yield data_line
                await asyncio.sleep(0)
                last_seen_index += 1
    
    except GeneratorExit:
        logger.info(f"Client disconnected from real stream for contract {contract_hash}")
    except Exception as e:
        logger.error(f"Error in real stream: {e}", exc_info=True)
