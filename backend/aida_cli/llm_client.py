import requests
import json
import time
from typing import List, Dict, Any, Optional

class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str, max_retries: int = 3):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.model = model
        self.max_retries = max_retries

    def chat_completion(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.0 # Deterministic for audit
        }
        
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        last_exception = None
        for attempt in range(self.max_retries):
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=120)
                response.raise_for_status()
                return response.json()
            except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt
                    print(f"LLM Call Failed (attempt {attempt + 1}/{self.max_retries}): {e}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    print(f"LLM Call Failed after {self.max_retries} attempts: {e}")
            except requests.exceptions.RequestException as e:
                print(f"LLM API Error: {e}")
                if e.response:
                    print(f"Response: {e.response.text}")
                raise
        raise last_exception

    def extract_content(self, response: Dict[str, Any]) -> Optional[str]:
        try:
            return response["choices"][0]["message"].get("content")
        except (KeyError, IndexError):
            return None

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            message = response["choices"][0]["message"]
            return message.get("tool_calls", [])
        except (KeyError, IndexError):
            return []

    def list_models(self) -> List[str]:
        url = f"{self.base_url}/models"
        headers = {
            "Authorization": f"Bearer {self.api_key}"
        }
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            return [model["id"] for model in data.get("data", [])]
        except Exception as e:
            print(f"Warning: Failed to fetch models: {e}")
            return []
