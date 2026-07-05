"""
AI integration: sends vulnerability summary to AI service.
Supports Google AI Studio and OpenAI-compatible endpoints (local LLMs).
"""
import json
import logging
import os
from pathlib import Path
from typing import List, Dict, Optional
import requests
from config import Config

logger = logging.getLogger(__name__)


def load_prompt_template(config: Config) -> str:
    """Load prompt template, preferring custom if it exists and is not empty."""
    custom_file = config.get('custom_prompt_file', 'prompts/custom.prompt')
    default_file = config.get('prompt_file', 'prompts/default_analysis.prompt')
    custom_path = Path(custom_file)
    if custom_path.exists() and custom_path.stat().st_size > 0:
        return custom_path.read_text()
    default_path = Path(default_file)
    if default_path.exists():
        return default_path.read_text()
    # Fallback minimal prompt
    return "You are a security expert. Analyze these vulnerabilities on {url}: {vulnerabilities}"


def call_google_ai(prompt: str, api_key: str, model: str, api_base: str) -> Optional[str]:
    """Call Google AI Studio (Gemini) generateContent endpoint."""
    url = f"{api_base}?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            # Extract text from candidates
            candidates = data.get('candidates', [])
            if candidates:
                return candidates[0].get('content', {}).get('parts', [{}])[0].get('text', '')
        else:
            logger.error(f"Google AI error: {resp.status_code} {resp.text}")
    except Exception as e:
        logger.error(f"Google AI request failed: {e}")
    return None


def call_openai_compatible(prompt: str, api_key: str, model: str, api_base: str) -> Optional[str]:
    """Call OpenAI-compatible chat completions endpoint (e.g., Ollama, LocalAI)."""
    url = api_base.rstrip('/') + '/v1/chat/completions'
    headers = {'Content-Type': 'application/json'}
    if api_key:
        headers['Authorization'] = f'Bearer {api_key}'
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=60)
        if resp.status_code == 200:
            data = resp.json()
            return data['choices'][0]['message']['content']
        else:
            logger.error(f"OpenAI-compatible error: {resp.status_code} {resp.text}")
    except Exception as e:
        logger.error(f"Request failed: {e}")
    return None


def analyze_vulnerabilities(url: str, vulnerabilities: List[Dict], config: Config) -> str:
    """
    Build prompt, send to AI, return response text.
    """
    template = load_prompt_template(config)
    vuln_text = json.dumps(vulnerabilities, indent=2) if vulnerabilities else "No vulnerabilities found."
    prompt = template.format(
        url=url,
        vulnerabilities=vuln_text,
        scan_date=__import__('datetime').datetime.now().isoformat()
    )
    provider = config.get('ai_provider', 'google')
    api_key = config.get('api_key', '')
    model = config.get('model', 'gemini-pro')
    api_base = config.get('api_base', 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent')

    if provider == 'google':
        if not api_key:
            raise ValueError("Google AI API key not set. Set it in Settings.")
        result = call_google_ai(prompt, api_key, model, api_base)
    else:
        # openai_compatible (local or remote)
        result = call_openai_compatible(prompt, api_key, model, api_base)

    if result:
        return result.strip()
    else:
        return "AI analysis could not be completed. Check logs and connectivity."
