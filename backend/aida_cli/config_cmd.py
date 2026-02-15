import sys
import os
import json
import argparse
import getpass
from .config import Config
from .llm_client import LLMClient


def validate_api_key(url, api_key):
    temp_client = LLMClient(url, api_key, "gpt-4o")
    models = temp_client.list_models()
    return models


def main():
    print("Interactive Configuration Wizard")
    print("--------------------------------")
    
    config = Config()
    
    current_url = config.get_llm_base_url() or "https://api.openai.com/v1"
    try:
        url = input(f"LLM Base URL [{current_url}]: ").strip()
    except EOFError:
        url = ""
    if not url:
        url = current_url
        
    while True:
        current_key = config.get_llm_api_key()
        masked_key = (current_key[:4] + "..." + current_key[-4:]) if current_key and len(current_key) > 8 else ""
        prompt = f"LLM API Key [{masked_key}]: " if masked_key else "LLM API Key: "
        try:
            api_key = getpass.getpass(prompt).strip()
        except EOFError:
            api_key = ""
        if not api_key:
            api_key = current_key

        if not api_key:
            print("Error: API Key is required.")
            continue

        print("Validating API Key...")
        models = validate_api_key(url, api_key)
        
        if not models:
            print("Error: Invalid API Key. Please check and try again.")
            config.data["llm"]["api_key"] = ""
            config.save()
            continue
            
        break
    
    print("Fetching available models...")
    selected_model = "gpt-4o"
    
    print("Available Models:")
    for i, m in enumerate(models):
        print(f"{i+1}. {m}")
    
    while True:
        try:
            selection = input(f"Select model (1-{len(models)}) or type name: ").strip()
        except EOFError:
            selection = ""
            
        if selection.isdigit():
            idx = int(selection) - 1
            if 0 <= idx < len(models):
                selected_model = models[idx]
                break
        elif selection:
            selected_model = selection
            break
        else:
            current_model = config.get_llm_model()
            if current_model in models:
                selected_model = current_model
                break
            elif models:
                selected_model = models[0]
                break
            else:
                break

    if "llm" not in config.data:
        config.data["llm"] = {}
    config.data["llm"]["base_url"] = url
    config.data["llm"]["api_key"] = api_key
    config.data["llm"]["model"] = selected_model
    config.save()
    print("Configuration updated successfully.")


if __name__ == "__main__":
    main()