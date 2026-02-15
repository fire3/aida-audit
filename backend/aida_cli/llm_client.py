import requests
import json
import time
from typing import List, Dict, Any, Optional

class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.model = model

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

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=120)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"LLM API Error: {e}")
            if e.response:
                print(f"Response: {e.response.text}")
            raise

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
