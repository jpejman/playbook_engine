# LLM Client Module
# Version: v0.2.0
# Timestamp: 2026-04-08

"""
LLM client for AI model integrations.
Provides real LLM API connections with environment-driven configuration.
"""

import os
import json
import logging
import requests
from typing import Dict, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LLMClient:
    """
    LLM client for AI model integrations.
    
    Provides real LLM API connections with environment-driven configuration,
    timeout handling, request/response logging, and error handling.
    """
    
    def __init__(self):
        """Initialize LLM client with environment variables."""
        self.api_key = os.getenv('LLM_API_KEY', '')
        self.model = os.getenv('LLM_MODEL', 'gpt-4')
        self.base_url = os.getenv('LLM_BASE_URL', 'https://api.openai.com/v1')
        self.generate_path = os.getenv('LLM_GENERATE_PATH', '/chat/completions')
        self.timeout_seconds = int(os.getenv('LLM_TIMEOUT_SECONDS', '30'))
        self.temperature = float(os.getenv('LLM_TEMPERATURE', '0.7'))
        self.max_tokens = int(os.getenv('LLM_MAX_TOKENS', '2000'))
        
        # Validate required configuration
        if not self.base_url:
            logger.warning("LLM_BASE_URL not set, using default")
        
        logger.info(f"LLM client initialized for model: {self.model}")
        logger.info(f"Base URL: {self.base_url}")
        logger.info(f"Timeout: {self.timeout_seconds}s")
        logger.info(f"Generate path: {self.generate_path}")
    
    def generate(self, prompt: str) -> Dict[str, Any]:
        """
        Generate text using LLM with comprehensive diagnostics.
        
        Args:
            prompt: Input prompt for generation
            
        Returns:
            Dictionary containing:
                - model: Model name used
                - raw_text: Raw response text from LLM
                - parsed_json: Parsed JSON response if valid, else None
                - request_id: Optional request identifier
                - status: "completed" or "failed"
                - diagnostics: Dictionary with diagnostic information
                    - response_size: Size of raw response in characters
                    - latency_seconds: API call latency
                    - error_classification: Error type if failed
                    - raw_payload: Full LLM response payload
                    - prompt_size: Size of input prompt in characters
        """
        logger.info(f"Generating text with prompt: {prompt[:100]}...")
        
        # Check if using Ollama API (different format)
        is_ollama = "/api/generate" in self.generate_path
        
        # Prepare request data based on API type
        if is_ollama:
            # Ollama format
            request_data = {
                "model": self.model,
                "prompt": prompt,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens
                },
                "stream": False  # Non-streaming for simplicity
            }
        else:
            # OpenAI-compatible format
            request_data = {
                "model": self.model,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": self.temperature,
                "max_tokens": self.max_tokens
            }
        
        # Log request (without sensitive data)
        safe_request_data = request_data.copy()
        if self.api_key:
            safe_request_data["api_key"] = "[REDACTED]"
        logger.debug(f"LLM request data: {json.dumps(safe_request_data, indent=2)}")
        
        # Prepare headers
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "VulnStrike-Playbook-Engine/1.0"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        # Make API call
        start_time = datetime.now()
        try:
            response = requests.post(
                f"{self.base_url}{self.generate_path}",
                headers=headers,
                json=request_data,
                timeout=self.timeout_seconds
            )
            response_time = (datetime.now() - start_time).total_seconds()
            
            # Log response info
            logger.info(f"LLM API call completed in {response_time:.2f}s, status: {response.status_code}")
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Extract response text based on API type
                raw_text = ""
                if is_ollama:
                    # Ollama format
                    raw_text = response_data.get("response", "")
                    model_used = response_data.get("model", self.model)
                    request_id = None  # Ollama doesn't provide request IDs
                else:
                    # OpenAI-compatible format
                    if "choices" in response_data and len(response_data["choices"]) > 0:
                        choice = response_data["choices"][0]
                        if "message" in choice and "content" in choice["message"]:
                            raw_text = choice["message"]["content"]
                        elif "text" in choice:
                            raw_text = choice["text"]
                    model_used = response_data.get("model", self.model)
                    request_id = response_data.get("id")
                
                # Try to parse as JSON
                parsed_json = None
                try:
                    parsed_json = json.loads(raw_text)
                except json.JSONDecodeError:
                    # Not JSON, that's OK
                    pass
                
                # Build diagnostics
                diagnostics = {
                    "response_size": len(raw_text),
                    "latency_seconds": response_time,
                    "error_classification": None,
                    "raw_payload": response_data,
                    "prompt_size": len(prompt),
                    "api_status_code": response.status_code,
                    "model_used": model_used
                }
                
                # Build result
                result = {
                    "model": model_used,
                    "raw_text": raw_text,
                    "parsed_json": parsed_json,
                    "request_id": request_id,
                    "status": "completed",
                    "diagnostics": diagnostics
                }
                
                # Log successful response (truncated)
                logger.debug(f"LLM response (truncated): {raw_text[:200]}...")
                logger.info(f"LLM generation successful, response length: {len(raw_text)} chars, latency: {response_time:.2f}s")
                
                return result
                
            else:
                # API error
                error_msg = f"LLM API returned status {response.status_code}"
                try:
                    error_detail = response.json()
                    error_msg += f": {error_detail}"
                except:
                    error_msg += f": {response.text[:200]}"
                
                logger.error(error_msg)
                
                # Classify error
                error_classification = self._classify_error(response.status_code, error_msg)
                
                diagnostics = {
                    "response_size": 0,
                    "latency_seconds": response_time,
                    "error_classification": error_classification,
                    "raw_payload": None,
                    "prompt_size": len(prompt),
                    "api_status_code": response.status_code,
                    "error_message": error_msg[:500]  # Truncate long error messages
                }
                
                return {
                    "model": self.model,
                    "raw_text": "",
                    "parsed_json": None,
                    "request_id": None,
                    "status": "failed",
                    "error": error_msg,
                    "diagnostics": diagnostics
                }
                
        except requests.exceptions.Timeout:
            logger.error(f"LLM API request timed out after {self.timeout_seconds}s")
            response_time = (datetime.now() - start_time).total_seconds()
            
            diagnostics = {
                "response_size": 0,
                "latency_seconds": response_time,
                "error_classification": "timeout",
                "raw_payload": None,
                "prompt_size": len(prompt),
                "api_status_code": None,
                "error_message": f"Request timeout after {self.timeout_seconds}s"
            }
            
            return {
                "model": self.model,
                "raw_text": "",
                "parsed_json": None,
                "request_id": None,
                "status": "failed",
                "error": f"Request timeout after {self.timeout_seconds}s",
                "diagnostics": diagnostics
            }
            
        except requests.exceptions.ConnectionError as e:
            logger.error(f"LLM API connection error: {e}")
            response_time = (datetime.now() - start_time).total_seconds()
            
            diagnostics = {
                "response_size": 0,
                "latency_seconds": response_time,
                "error_classification": "connection_error",
                "raw_payload": None,
                "prompt_size": len(prompt),
                "api_status_code": None,
                "error_message": f"Connection error: {str(e)}"
            }
            
            return {
                "model": self.model,
                "raw_text": "",
                "parsed_json": None,
                "request_id": None,
                "status": "failed",
                "error": f"Connection error: {str(e)}",
                "diagnostics": diagnostics
            }
            
        except Exception as e:
            logger.error(f"LLM API unexpected error: {e}")
            response_time = (datetime.now() - start_time).total_seconds()
            
            diagnostics = {
                "response_size": 0,
                "latency_seconds": response_time,
                "error_classification": "unknown_error",
                "raw_payload": None,
                "prompt_size": len(prompt),
                "api_status_code": None,
                "error_message": f"Unexpected error: {str(e)}"
            }
            
            return {
                "model": self.model,
                "raw_text": "",
                "parsed_json": None,
                "request_id": None,
                "status": "failed",
                "error": f"Unexpected error: {str(e)}",
                "diagnostics": diagnostics
            }
    
    def _classify_error(self, status_code: int, error_msg: str) -> str:
        """Classify LLM API errors."""
        if status_code == 429:
            return "rate_limit"
        elif status_code == 401:
            return "authentication_error"
        elif status_code == 403:
            return "permission_denied"
        elif status_code >= 500:
            return "server_error"
        elif status_code >= 400:
            return "client_error"
        elif "timeout" in error_msg.lower():
            return "timeout"
        elif "connection" in error_msg.lower():
            return "connection_error"
        else:
            return "unknown_error"
    
    def evaluate(self, text: str, criteria: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluate text using LLM.
        
        Args:
            text: Text to evaluate
            criteria: Evaluation criteria
            
        Returns:
            Dictionary containing evaluation scores and feedback
        """
        logger.info(f"Evaluating text: {text[:100]}...")
        
        # Build evaluation prompt
        criteria_text = json.dumps(criteria, indent=2) if criteria else "general quality assessment"
        prompt = f"""Evaluate the following text based on these criteria:
        
Criteria:
{criteria_text}

Text to evaluate:
{text}

Provide evaluation in JSON format with scores and feedback."""
        
        # Use generate method for evaluation
        return self.generate(prompt)
    
    def chat(self, messages: list, **kwargs) -> Dict[str, Any]:
        """
        Chat completion using LLM.
        
        Args:
            messages: List of message dictionaries
            **kwargs: Additional parameters
            
        Returns:
            Dictionary containing chat response
        """
        logger.info(f"Chat completion with {len(messages)} messages")
        
        # Check if using Ollama API (different format)
        is_ollama = "/api/generate" in self.generate_path
        
        if is_ollama:
            # Convert messages to a single prompt for Ollama
            prompt = ""
            for msg in messages:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                prompt += f"{role}: {content}\n"
            
            # Use generate method for Ollama
            return self.generate(prompt)
        
        # OpenAI-compatible format
        request_data = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get('temperature', self.temperature),
            "max_tokens": kwargs.get('max_tokens', self.max_tokens)
        }
        
        # Log request (without sensitive data)
        safe_request_data = request_data.copy()
        if self.api_key:
            safe_request_data["api_key"] = "[REDACTED]"
        logger.debug(f"LLM chat request data: {json.dumps(safe_request_data, indent=2)}")
        
        # Prepare headers
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "VulnStrike-Playbook-Engine/1.0"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        # Make API call
        start_time = datetime.now()
        try:
            response = requests.post(
                f"{self.base_url}{self.generate_path}",
                headers=headers,
                json=request_data,
                timeout=self.timeout_seconds
            )
            response_time = (datetime.now() - start_time).total_seconds()
            
            # Log response info
            logger.info(f"LLM chat API call completed in {response_time:.2f}s, status: {response.status_code}")
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Extract response text
                raw_text = ""
                if "choices" in response_data and len(response_data["choices"]) > 0:
                    choice = response_data["choices"][0]
                    if "message" in choice and "content" in choice["message"]:
                        raw_text = choice["message"]["content"]
                    elif "text" in choice:
                        raw_text = choice["text"]
                
                # Build result
                result = {
                    "model": response_data.get("model", self.model),
                    "raw_text": raw_text,
                    "parsed_json": None,  # Chat responses typically aren't JSON
                    "request_id": response_data.get("id"),
                    "status": "completed"
                }
                
                # Log successful response (truncated)
                logger.debug(f"LLM chat response (truncated): {raw_text[:200]}...")
                logger.info(f"LLM chat successful, response length: {len(raw_text)} chars")
                
                return result
                
            else:
                # API error
                error_msg = f"LLM chat API returned status {response.status_code}"
                try:
                    error_detail = response.json()
                    error_msg += f": {error_detail}"
                except:
                    error_msg += f": {response.text[:200]}"
                
                logger.error(error_msg)
                return {
                    "model": self.model,
                    "raw_text": "",
                    "parsed_json": None,
                    "request_id": None,
                    "status": "failed",
                    "error": error_msg
                }
                
        except requests.exceptions.Timeout:
            logger.error(f"LLM chat API request timed out after {self.timeout_seconds}s")
            return {
                "model": self.model,
                "raw_text": "",
                "parsed_json": None,
                "request_id": None,
                "status": "failed",
                "error": f"Request timeout after {self.timeout_seconds}s"
            }
            
        except Exception as e:
            logger.error(f"LLM chat API unexpected error: {e}")
            return {
                "model": self.model,
                "raw_text": "",
                "parsed_json": None,
                "request_id": None,
                "status": "failed",
                "error": f"Unexpected error: {str(e)}"
            }


# Convenience function for quick access
def get_llm_client() -> LLMClient:
    """
    Factory function to get an LLM client instance.
    
    Returns:
        LLMClient instance
    """
    return LLMClient()