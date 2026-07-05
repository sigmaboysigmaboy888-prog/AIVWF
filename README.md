# AIVWF – AI Automated Vulnerability Web Founder

AIVWF is a powerful, fully terminal-based web vulnerability scanner with integrated AI analysis. It runs entirely in Termux / Linux, requires no paid dependencies, and supports both online (Google AI) and local LLMs.

![AIVWF Banner](https://via.placeholder.com/800x200?text=AIVWF)

## Features

- **Interactive Rich Terminal Menu** – Beautiful UI with panels, tables, and colors.
- **Comprehensive Scanning** – XSS, SQLi, path traversal, sensitive file leaks, open redirects, missing security headers, CORS misconfigurations.
- **Asynchronous Engine** – Fast concurrent scanning using `aiohttp`.
- **AI-Powered Analysis** – Sends found vulnerabilities to AI for risk explanation and remediation steps.
- **Custom Prompt System** – Edit prompt templates directly from the menu.
- **Multiple Export Formats** – JSON, CSV, HTML reports (Jinja2 templated).
- **Scan History** – SQLite database stores all results locally.
- **Configurable** – Timeout, concurrency, user‑agent, AI provider, custom endpoints.

## Installation

### 1. System Dependencies (Termux)
```bash
pkg update && pkg upgrade
pkg install python3 git expat
