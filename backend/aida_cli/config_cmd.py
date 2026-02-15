import sys
import os
import json
import argparse
import getpass
from .config import Config
from .llm_client import LLMClient


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
        return

    print("Fetching available models...")
    temp_client = LLMClient(url, api_key, "gpt-4o")
    models = temp_client.list_models()
    
    selected_model = "gpt-4o"
    if not models:
        print("Warning: Could not fetch models. Using default 'gpt-4o'.")
        try:
            manual_model = input(f"Enter model name [gpt-4o]: ").strip()
            if manual_model:
                selected_model = manual_model
        except EOFError:
            pass
    else:
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