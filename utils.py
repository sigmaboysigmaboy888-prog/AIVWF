"""
Utility functions: logging, banner, URL normalizer.
"""
import logging
import sys
from urllib.parse import urlparse, urlunparse
from rich.console import Console
from rich.text import Text

def setup_logging():
    logging.basicConfig(
        filename='aivwf.log',
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    # Also log to stderr if needed, but keep quiet
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    logging.getLogger().addHandler(console_handler)

def print_banner():
    console = Console()
    banner = r"""
    █████╗ ██╗██╗   ██╗██╗    ██╗███████╗
   ██╔══██╗██║██║   ██║██║    ██║██╔════╝
   ███████║██║██║   ██║██║ █╗ ██║█████╗  
   ██╔══██║██║╚██╗ ██╔╝██║███╗██║██╔══╝  
   ██║  ██║██║ ╚████╔╝ ╚███╔███╔╝██║     
   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚══╝╚══╝ ╚═╝     
   AI Automated Vulnerability Web Founder
    """
    console.print(Text(banner, style="bold magenta"))

def normalize_url(url: str) -> str:
    """Add scheme if missing, remove trailing slash."""
    url = url.strip()
    if not url:
        return ''
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    # Remove default ports, fragment
    netloc = parsed.netloc
    if (parsed.scheme == 'http' and netloc.endswith(':80')):
        netloc = netloc[:-3]
    elif (parsed.scheme == 'https' and netloc.endswith(':443')):
        netloc = netloc[:-4]
    path = parsed.path.rstrip('/') or '/'
    normalized = urlunparse((parsed.scheme, netloc, path, parsed.params, parsed.query, ''))
    return normalized
