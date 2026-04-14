"""
Generation Diagnostics Module
Version: v1.0.0
Timestamp (UTC): 2026-04-13

Purpose:
- Capture comprehensive diagnostics for LLM generation runs
- Store debug information in database and files
- Classify errors for analysis
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)


class GenerationDiagnostics:
    """Manages generation diagnostics collection and storage."""
    
    def __init__(self, db_client=None):
        self.db_client = db_client
        self.debug_info = {}
        
    def capture_llm_result(self, llm_result: Dict[str, Any]) -> Dict[str, Any]:
        """Capture diagnostics from LLM result."""
        
        diagnostics = {
            "captured_at": datetime.utcnow().isoformat(),
            "llm_status": llm_result.get("status", "unknown"),
            "model_used": llm_result.get("model", "unknown"),
            "request_id": llm_result.get("request_id"),
            "has_parsed_json": llm_result.get("parsed_json") is not None,
            "raw_response_length": len(llm_result.get("raw_text", "")),
            "error_message": llm_result.get("error"),
        }
        
        # Add diagnostics from LLM client if available
        if "diagnostics" in llm_result:
            llm_diagnostics = llm_result["diagnostics"]
            diagnostics.update({
                "response_size": llm_diagnostics.get("response_size"),
                "latency_seconds": llm_diagnostics.get("latency_seconds"),
                "error_classification": llm_diagnostics.get("error_classification"),
                "prompt_size": llm_diagnostics.get("prompt_size"),
                "api_status_code": llm_diagnostics.get("api_status_code"),
                "model_used": llm_diagnostics.get("model_used", llm_result.get("model")),
            })
            
            # Store raw payload (truncated if too large)
            raw_payload = llm_diagnostics.get("raw_payload")
            if raw_payload:
                # Truncate large payloads for storage
                payload_str = json.dumps(raw_payload)
                if len(payload_str) > 10000:
                    diagnostics["raw_payload_truncated"] = True
                    diagnostics["raw_payload_preview"] = payload_str[:5000]
                else:
                    diagnostics["raw_payload"] = raw_payload
        
        # Classify the overall result
        diagnostics["overall_classification"] = self._classify_generation_result(llm_result)
        
        self.debug_info = diagnostics
        return diagnostics
    
    def _classify_generation_result(self, llm_result: Dict[str, Any]) -> str:
        """Classify the generation result for analysis."""
        
        status = llm_result.get("status", "unknown")
        
        if status == "completed":
            raw_text = llm_result.get("raw_text", "")
            parsed_json = llm_result.get("parsed_json")
            
            if not raw_text:
                return "empty_response"
            elif parsed_json is None:
                return "schema_validation_failure"
            else:
                return "success"
        
        elif status == "failed":
            error = llm_result.get("error", "").lower()
            diagnostics = llm_result.get("diagnostics", {})
            error_classification = diagnostics.get("error_classification", "")
            
            # Use error classification from LLM client if available
            if error_classification:
                if error_classification == "timeout":
                    return "timeout"
                elif error_classification == "connection_error":
                    return "connection_error"
                elif error_classification == "rate_limit":
                    return "rate_limit"
                elif error_classification == "server_error":
                    return "server_error"
            
            # Fallback to error message analysis
            if "timeout" in error:
                return "timeout"
            elif "connection" in error:
                return "connection_error"
            elif "rate limit" in error or "429" in error:
                return "rate_limit"
            elif "empty" in error or "no response" in error:
                return "empty_response"
            else:
                return "llm_error"
        
        return "unknown"
    
    def save_to_database(self, generation_run_id: int) -> bool:
        """Save diagnostics to generation_debug_info table."""
        
        if not self.db_client:
            logger.warning("No database client provided, skipping database save")
            return False
        
        try:
            # Prepare data for database
            debug_data = {
                "generation_run_id": generation_run_id,
                "raw_llm_payload": json.dumps(self.debug_info.get("raw_payload")) if self.debug_info.get("raw_payload") else None,
                "response_size_bytes": self.debug_info.get("response_size", 0),
                "latency_milliseconds": int((self.debug_info.get("latency_seconds", 0) * 1000)),
                "error_classification": self.debug_info.get("error_classification"),
                "prompt_size_chars": self.debug_info.get("prompt_size", 0),
                "api_status_code": self.debug_info.get("api_status_code"),
                "model_used": self.debug_info.get("model_used"),
                "error_message": self.debug_info.get("error_message"),
            }
            
            # Insert into generation_debug_info table
            insert_sql = """
            INSERT INTO generation_debug_info (
                generation_run_id, raw_llm_payload, response_size_bytes,
                latency_milliseconds, error_classification, prompt_size_chars,
                api_status_code, model_used, error_message
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (generation_run_id) DO UPDATE SET
                raw_llm_payload = EXCLUDED.raw_llm_payload,
                response_size_bytes = EXCLUDED.response_size_bytes,
                latency_milliseconds = EXCLUDED.latency_milliseconds,
                error_classification = EXCLUDED.error_classification,
                prompt_size_chars = EXCLUDED.prompt_size_chars,
                api_status_code = EXCLUDED.api_status_code,
                model_used = EXCLUDED.model_used,
                error_message = EXCLUDED.error_message,
                created_at = NOW()
            """
            
            self.db_client.execute(insert_sql, (
                debug_data["generation_run_id"],
                debug_data["raw_llm_payload"],
                debug_data["response_size_bytes"],
                debug_data["latency_milliseconds"],
                debug_data["error_classification"],
                debug_data["prompt_size_chars"],
                debug_data["api_status_code"],
                debug_data["model_used"],
                debug_data["error_message"],
            ))
            
            logger.info(f"Saved generation diagnostics to database for run {generation_run_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save generation diagnostics to database: {e}")
            return False
    
    def save_to_file(self, generation_run_id: int, cve_id: str) -> Optional[str]:
        """Save diagnostics to JSON file in logs/runs/ directory."""
        
        try:
            # Create directory for this run
            run_dir = Path("logs") / "runs" / str(generation_run_id)
            run_dir.mkdir(parents=True, exist_ok=True)
            
            # Prepare full debug data
            debug_data = {
                "generation_run_id": generation_run_id,
                "cve_id": cve_id,
                "captured_at": datetime.utcnow().isoformat(),
                "diagnostics": self.debug_info,
                "classification": self.debug_info.get("overall_classification", "unknown"),
            }
            
            # Save to file
            file_path = run_dir / "generation_debug.json"
            with open(file_path, 'w') as f:
                json.dump(debug_data, f, indent=2, default=str)
            
            logger.info(f"Saved generation diagnostics to file: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Failed to save generation diagnostics to file: {e}")
            return None
    
    def update_generation_run_with_diagnostics(self, generation_run_id: int, llm_error_info: Optional[str] = None) -> bool:
        """Update generation_runs table with llm_error_info containing diagnostics."""
        
        if not self.db_client:
            logger.warning("No database client provided, skipping generation run update")
            return False
        
        try:
            # Prepare llm_error_info JSON
            error_info = {
                "diagnostics": self.debug_info,
                "classification": self.debug_info.get("overall_classification", "unknown"),
                "captured_at": datetime.utcnow().isoformat(),
            }
            
            # Merge with existing llm_error_info if provided
            if llm_error_info:
                try:
                    existing_info = json.loads(llm_error_info)
                    if isinstance(existing_info, dict):
                        error_info.update(existing_info)
                except json.JSONDecodeError:
                    # If existing info is not JSON, keep it as a field
                    error_info["existing_error_info"] = llm_error_info
            
            # Update generation_runs table
            update_sql = """
            UPDATE generation_runs 
            SET llm_error_info = %s
            WHERE id = %s
            """
            
            self.db_client.execute(update_sql, (json.dumps(error_info), generation_run_id))
            
            logger.info(f"Updated generation run {generation_run_id} with diagnostics")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update generation run with diagnostics: {e}")
            return False


def create_generation_summary(run_ids: list, db_client) -> Dict[str, Any]:
    """Create a summary of generation results for analysis."""
    
    try:
        # Query generation_debug_info table
        placeholders = ','.join(['%s'] * len(run_ids))
        query = f"""
        SELECT 
            error_classification,
            COUNT(*) as count,
            AVG(latency_milliseconds) as avg_latency_ms,
            AVG(response_size_bytes) as avg_response_size,
            MIN(created_at) as first_occurrence,
            MAX(created_at) as last_occurrence
        FROM generation_debug_info
        WHERE generation_run_id IN ({placeholders})
        GROUP BY error_classification
        ORDER BY count DESC
        """
        
        results = db_client.fetch_all(query, tuple(run_ids))
        
        # Query generation_runs for overall status
        status_query = f"""
        SELECT 
            status,
            COUNT(*) as count
        FROM generation_runs
        WHERE id IN ({placeholders})
        GROUP BY status
        ORDER BY count DESC
        """
        
        status_results = db_client.fetch_all(status_query, tuple(run_ids))
        
        summary = {
            "total_runs": len(run_ids),
            "error_classification_breakdown": results or [],
            "status_breakdown": status_results or [],
            "generated_at": datetime.utcnow().isoformat(),
        }
        
        # Calculate success rate
        success_count = 0
        for status in status_results:
            if status['status'] == 'completed':
                success_count = status['count']
                break
        
        summary["success_rate"] = (success_count / len(run_ids)) * 100 if run_ids else 0
        
        return summary
        
    except Exception as e:
        logger.error(f"Failed to create generation summary: {e}")
        return {"error": str(e)}