"""
Asynchronous web vulnerability scanner.
Supports XSS, SQLi, path traversal, sensitive files, headers, open redirects.
"""
import asyncio
import random
import re
import socket
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import aiohttp
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)

# User-agent rotation pool
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "AIVWF/1.0 (Security Scanner)",
]

# Load wordlists
def load_wordlist(filename: str) -> List[str]:
    path = f"wordlists/{filename}"
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.warning(f"Wordlist {filename} not found, using empty list.")
        return []

SENSITIVE_PATHS = load_wordlist("sensitive_files.txt")
SQLI_PAYLOADS = load_wordlist("sqli_payloads.txt")
XSS_PAYLOADS = load_wordlist("xss_vectors.txt")
COMMON_PATHS = load_wordlist("common_paths.txt")

HEADER_CHECKS = {
    "Content-Security-Policy": "Missing CSP header",
    "Strict-Transport-Security": "Missing HSTS header",
    "X-Frame-Options": "Missing X-Frame-Options header",
    "X-Content-Type-Options": "Missing X-Content-Type-Options header",
    "Referrer-Policy": "Missing Referrer-Policy header",
    "Permissions-Policy": "Missing Permissions-Policy header",
}


async def fetch(session: aiohttp.ClientSession, url: str, method='GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
    """Generic async fetch with retry logic and error handling."""
    retries = 2
    for attempt in range(retries + 1):
        try:
            async with session.request(method, url, **kwargs) as response:
                return response
        except (aiohttp.ClientConnectionError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"Request attempt {attempt+1} failed for {url}: {e}")
            if attempt == retries:
                logger.error(f"All attempts failed for {url}")
                return None
            await asyncio.sleep(1)  # brief pause before retry
    return None


async def check_headers(url: str, response: aiohttp.ClientResponse) -> List[Dict]:
    """Analyze security headers."""
    vulns = []
    for header, message in HEADER_CHECKS.items():
        if header not in response.headers:
            vulns.append({
                'type': 'Missing Header',
                'payload': header,
                'evidence': message,
                'severity': 'medium'
            })
    # CORS misconfig: check Access-Control-Allow-Origin with wildcard
    acao = response.headers.get('Access-Control-Allow-Origin', '')
    if acao == '*':
        vulns.append({
            'type': 'CORS Misconfiguration',
            'payload': 'Access-Control-Allow-Origin: *',
            'evidence': 'Wildcard CORS allows any origin',
            'severity': 'high'
        })
    return vulns


async def check_sensitive_files(base_url: str, session: aiohttp.ClientSession) -> List[Dict]:
    """Check for exposed sensitive files/directories."""
    vulns = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in SENSITIVE_PATHS:
        test_url = urljoin(base, path)
        resp = await fetch(session, test_url, method='HEAD', allow_redirects=False)
        if resp and resp.status == 200:
            vulns.append({
                'type': 'Sensitive File Exposed',
                'payload': path,
                'evidence': f'HTTP 200 at {test_url}',
                'severity': 'high'
            })
    return vulns


async def check_open_redirect(url: str, session: aiohttp.ClientSession) -> List[Dict]:
    """Basic open redirect test by injecting common redirect parameters."""
    vulns = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    redirect_params = ['redirect', 'url', 'next', 'return', 'goto', 'target']
    payload = 'https://evil.com'
    for param in redirect_params:
        if param in query_params:
            new_params = query_params.copy()
            new_params[param] = [payload]
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            resp = await fetch(session, test_url, allow_redirects=False)
            if resp and resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get('Location', '')
                if payload in location:
                    vulns.append({
                        'type': 'Open Redirect',
                        'payload': f'{param}={payload}',
                        'evidence': f'Redirects to {location}',
                        'severity': 'medium'
                    })
    return vulns


async def inject_params(url: str, method='GET', data: Optional[Dict] = None, session: aiohttp.ClientSession = None, payloads: List[str] = None, param_name: str = None) -> List[Dict]:
    """Inject payloads into a parameter and check response for reflection/errors."""
    vulns = []
    if not payloads:
        return []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    test_params = query_params.copy() if query_params else {'q': ['test']}
    for param in test_params:
        for payload in payloads:
            new_params = test_params.copy()
            new_params[param] = [payload]
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            resp = await fetch(session, test_url, method=method, data=data)
            if not resp:
                continue
            text = await resp.text()
            # XSS check: look for unescaped payload
            if payload in text:
                # Simple reflection; could be enhanced
                vulns.append({
                    'type': 'Reflected XSS',
                    'payload': payload,
                    'evidence': f'Payload reflected in response on param {param}',
                    'severity': 'high'
                })
            # SQLi check: look for database error patterns
            sql_errors = [
                'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite',
                'UNION SELECT', 'DB Error', 'ODBC Driver'
            ]
            if any(err.lower() in text.lower() for err in sql_errors):
                vulns.append({
                    'type': 'SQL Injection',
                    'payload': payload,
                    'evidence': f'SQL error detected in response',
                    'severity': 'critical'
                })
    return vulns


async def scan_url(url: str, config, session: Optional[aiohttp.ClientSession] = None) -> Dict[str, Any]:
    """
    Main scan function for a single URL.
    Returns dict with 'vulnerabilities' list and 'summary' string.
    """
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    if not session:
        timeout = aiohttp.ClientTimeout(total=config.get('timeout', 30))
        headers = {'User-Agent': config.get('user_agent', random.choice(USER_AGENTS))}
        # Force IPv4 to avoid common hanging on some networks
        conn = aiohttp.TCPConnector(limit=config.get('concurrency', 10), family=socket.AF_INET)
        async with aiohttp.ClientSession(timeout=timeout, headers=headers, connector=conn) as session:
            return await _scan(url, config, session)
    else:
        return await _scan(url, config, session)


async def _scan(url: str, config, session: aiohttp.ClientSession) -> Dict[str, Any]:
    vulnerabilities = []
    logger.info(f"Scanning {url}")

    # 1. Fetch main page
    resp = await fetch(session, url)
    if not resp or resp.status >= 500:
        return {'vulnerabilities': [], 'summary': f'Failed to fetch URL (status {resp.status if resp else "unknown"})'}
    text = await resp.text()
    headers = resp.headers

    # 2. Header analysis
    vulnerabilities.extend(await check_headers(url, resp))

    # 3. Sensitive file checks
    vulnerabilities.extend(await check_sensitive_files(url, session))

    # 4. Open redirect detection
    vulnerabilities.extend(await check_open_redirect(url, session))

    # 5. Parameter injection (XSS & SQLi)
    soup = BeautifulSoup(text, 'lxml')
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        data = {}
        for inp in inputs:
            name = inp.get('name')
            if name:
                data[name] = inp.get('value', 'test')
        form_url = urljoin(url, action) if action else url
        for name in data:
            for payload in XSS_PAYLOADS:
                test_data = data.copy()
                test_data[name] = payload
                if method == 'post':
                    resp_form = await fetch(session, form_url, method='POST', data=test_data)
                else:
                    parsed = urlparse(form_url)
                    new_query = urlencode(test_data, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    resp_form = await fetch(session, test_url)
                if resp_form:
                    resp_text = await resp_form.text()
                    if payload in resp_text:
                        vulnerabilities.append({
                            'type': 'Reflected XSS (Form)',
                            'payload': payload,
                            'evidence': f'Form {name} at {form_url}',
                            'severity': 'high'
                        })
                    sql_errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite',
                                  'UNION SELECT', 'DB Error']
                    if any(err.lower() in resp_text.lower() for err in sql_errors):
                        vulnerabilities.append({
                            'type': 'SQL Injection (Form)',
                            'payload': payload,
                            'evidence': f'SQL error on {form_url}',
                            'severity': 'critical'
                        })
    if urlparse(url).query:
        vulns_param = await inject_params(url, session=session, payloads=XSS_PAYLOADS+SQLI_PAYLOADS)
        vulnerabilities.extend(vulns_param)

    # Deduplicate
    seen = set()
    unique_vulns = []
    for v in vulnerabilities:
        key = (v['type'], v.get('payload', ''), v.get('evidence', '')[:100])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    summary = f"Scan of {url} completed. Found {len(unique_vulns)} vulnerabilities."
    if unique_vulns:
        critical = sum(1 for v in unique_vulns if v.get('severity') == 'critical')
        high = sum(1 for v in unique_vulns if v.get('severity') == 'high')
        summary += f" ({critical} critical, {high} high)"
    return {'vulnerabilities': unique_vulns, 'summary': summary}


async def bulk_scan(urls: List[str], config) -> Dict[str, Dict]:
    """Scan multiple URLs concurrently."""
    timeout = aiohttp.ClientTimeout(total=config.get('timeout', 30))
    headers = {'User-Agent': config.get('user_agent', random.choice(USER_AGENTS))}
    conn = aiohttp.TCPConnector(limit=config.get('concurrency', 10), family=socket.AF_INET)
    async with aiohttp.ClientSession(timeout=timeout, headers=headers, connector=conn) as session:
        tasks = [scan_url(url, config, session) for url in urls]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
    results = {}
    for url, res in zip(urls, results_list):
        if isinstance(res, Exception):
            results[url] = {'vulnerabilities': [], 'summary': f'Error: {str(res)}'}
        else:
            results[url] = res
    return results                if payload in location:
                    vulns.append({
                        'type': 'Open Redirect',
                        'payload': f'{param}={payload}',
                        'evidence': f'Redirects to {location}',
                        'severity': 'medium'
                    })
    return vulns


async def inject_params(url: str, method='GET', data: Optional[Dict] = None, session: aiohttp.ClientSession = None, payloads: List[str] = None, param_name: str = None) -> List[Dict]:
    """Inject payloads into a parameter and check response for reflection/errors."""
    vulns = []
    if not payloads:
        return []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    test_params = query_params.copy() if query_params else {'q': ['test']}
    for param in test_params:
        for payload in payloads:
            new_params = test_params.copy()
            new_params[param] = [payload]
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            resp = await fetch(session, test_url, method=method, data=data)
            if not resp:
                continue
            text = await resp.text()
            # XSS check: look for unescaped payload
            if payload in text:
                # Simple reflection; could be enhanced
                vulns.append({
                    'type': 'Reflected XSS',
                    'payload': payload,
                    'evidence': f'Payload reflected in response on param {param}',
                    'severity': 'high'
                })
            # SQLi check: look for database error patterns
            sql_errors = [
                'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite',
                'UNION SELECT', 'DB Error', 'ODBC Driver'
            ]
            if any(err.lower() in text.lower() for err in sql_errors):
                vulns.append({
                    'type': 'SQL Injection',
                    'payload': payload,
                    'evidence': f'SQL error detected in response',
                    'severity': 'critical'
                })
    return vulns


async def scan_url(url: str, config, session: Optional[aiohttp.ClientSession] = None) -> Dict[str, Any]:
    """
    Main scan function for a single URL.
    Returns dict with 'vulnerabilities' list and 'summary' string.
    """
    url = normalize_url(url)
    if not url:
        return {'vulnerabilities': [], 'summary': 'Invalid URL'}
    if not session:
        timeout = aiohttp.ClientTimeout(total=config.get('timeout', 15))
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        conn = aiohttp.TCPConnector(limit=config.get('concurrency', 10))
        async with aiohttp.ClientSession(timeout=timeout, headers=headers, connector=conn) as session:
            return await _scan(url, config, session)
    else:
        return await _scan(url, config, session)


async def _scan(url: str, config, session: aiohttp.ClientSession) -> Dict[str, Any]:
    vulnerabilities = []
    logger.info(f"Scanning {url}")

    # 1. Fetch main page
    resp = await fetch(session, url)
    if not resp or resp.status >= 500:
        return {'vulnerabilities': [], 'summary': f'Failed to fetch URL (status {resp.status if resp else "unknown"})'}
    text = await resp.text()
    headers = resp.headers

    # 2. Header analysis
    vulnerabilities.extend(await check_headers(url, resp))

    # 3. Sensitive file checks
    vulnerabilities.extend(await check_sensitive_files(url, session))

    # 4. Open redirect detection
    vulnerabilities.extend(await check_open_redirect(url, session))

    # 5. Parameter injection (XSS & SQLi)
    # Parse forms if any
    soup = BeautifulSoup(text, 'lxml')
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        data = {}
        for inp in inputs:
            name = inp.get('name')
            if name:
                data[name] = inp.get('value', 'test')
        form_url = urljoin(url, action) if action else url
        # Inject XSS payloads into each input
        for name in data:
            for payload in XSS_PAYLOADS:
                test_data = data.copy()
                test_data[name] = payload
                if method == 'post':
                    resp_form = await fetch(session, form_url, method='POST', data=test_data)
                else:
                    # GET: build query
                    parsed = urlparse(form_url)
                    new_query = urlencode(test_data, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    resp_form = await fetch(session, test_url)
                if resp_form:
                    resp_text = await resp_form.text()
                    if payload in resp_text:
                        vulnerabilities.append({
                            'type': 'Reflected XSS (Form)',
                            'payload': payload,
                            'evidence': f'Form {name} at {form_url}',
                            'severity': 'high'
                        })
                    sql_errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite',
                                  'UNION SELECT', 'DB Error']
                    if any(err.lower() in resp_text.lower() for err in sql_errors):
                        vulnerabilities.append({
                            'type': 'SQL Injection (Form)',
                            'payload': payload,
                            'evidence': f'SQL error on {form_url}',
                            'severity': 'critical'
                        })
    # Also inject URL parameters if any
    if urlparse(url).query:
        vulns_param = await inject_params(url, session=session, payloads=XSS_PAYLOADS+SQLI_PAYLOADS)
        vulnerabilities.extend(vulns_param)

    # Deduplicate
    seen = set()
    unique_vulns = []
    for v in vulnerabilities:
        key = (v['type'], v.get('payload', ''), v.get('evidence', '')[:100])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)

    summary = f"Scan of {url} completed. Found {len(unique_vulns)} vulnerabilities."
    if unique_vulns:
        critical = sum(1 for v in unique_vulns if v.get('severity') == 'critical')
        high = sum(1 for v in unique_vulns if v.get('severity') == 'high')
        summary += f" ({critical} critical, {high} high)"
    return {'vulnerabilities': unique_vulns, 'summary': summary}


async def bulk_scan(urls: List[str], config) -> Dict[str, Dict]:
    """Scan multiple URLs concurrently."""
    timeout = aiohttp.ClientTimeout(total=config.get('timeout', 15))
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    conn = aiohttp.TCPConnector(limit=config.get('concurrency', 10))
    async with aiohttp.ClientSession(timeout=timeout, headers=headers, connector=conn) as session:
        tasks = [scan_url(url, config, session) for url in urls]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
    results = {}
    for url, res in zip(urls, results_list):
        if isinstance(res, Exception):
            results[url] = {'vulnerabilities': [], 'summary': f'Error: {str(res)}'}
        else:
            results[url] = res
    return results
