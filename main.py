#!/usr/bin/env python3
"""
AIVWF – AI Automated Vulnerability Web Founder
Main interactive menu entry point.
"""
import asyncio
import os
import sys
import traceback
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich import box
from prompt_toolkit import prompt as pt_prompt
from prompt_toolkit.completion import WordCompleter

from config import Config
from database import Database
from scanner import scan_url, bulk_scan
from ai_engine import analyze_vulnerabilities
from reporter import export_report
from utils import setup_logging, print_banner, normalize_url

console = Console()
db = Database()
config = Config()


def single_scan():
    """Interactive single URL scan."""
    url = pt_prompt("Enter target URL: ", completer=WordCompleter(['http://', 'https://']))
    url = normalize_url(url)
    if not url:
        console.print("[red]Invalid URL. Aborting.[/red]")
        return
    console.print(f"[cyan]Scanning {url} ...[/cyan]")
    try:
        result = asyncio.run(scan_url(url, config))
        if result:
            vulnerabilities = result.get('vulnerabilities', [])
            summary = result.get('summary', 'No issues found.')
            console.print(Panel(summary, title="Scan Summary", border_style="green"))
            if vulnerabilities:
                table = Table(title="Found Vulnerabilities", box=box.ROUNDED)
                table.add_column("Type", style="red")
                table.add_column("Payload", style="yellow")
                table.add_column("Evidence", style="dim")
                for v in vulnerabilities:
                    table.add_row(v['type'], v.get('payload', ''), v.get('evidence', '')[:80])
                console.print(table)
                # Store in database
                scan_id = db.insert_scan(url, result)
                for v in vulnerabilities:
                    db.insert_vulnerability(scan_id, v['type'], v.get('payload', ''), v.get('evidence', ''))
                console.print(f"[green]Results saved (Scan ID: {scan_id})[/green]")
            else:
                console.print("[green]No vulnerabilities detected.[/green]")
                db.insert_scan(url, {'vulnerabilities': [], 'summary': summary})
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        logging.exception("Scan failed")


def bulk_scan_menu():
    """Bulk scan from file."""
    file_path = pt_prompt("Path to file with URLs (one per line): ")
    if not os.path.isfile(file_path):
        console.print("[red]File not found.[/red]")
        return
    with open(file_path) as f:
        urls = [normalize_url(line.strip()) for line in f if line.strip()]
    console.print(f"[cyan]Bulk scanning {len(urls)} URLs ...[/cyan]")
    try:
        results = asyncio.run(bulk_scan(urls, config))
        for url, result in results.items():
            console.print(Panel(f"{url}: {result.get('summary', 'No issues')}", title="Result"))
            scan_id = db.insert_scan(url, result)
            for v in result.get('vulnerabilities', []):
                db.insert_vulnerability(scan_id, v['type'], v.get('payload', ''), v.get('evidence', ''))
        console.print("[green]Bulk scan complete. Results stored.[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def ai_analysis_menu():
    """Run AI analysis on a previous scan."""
    scans = db.get_all_scans(limit=20)
    if not scans:
        console.print("[yellow]No scans in history. Perform a scan first.[/yellow]")
        return
    table = Table(title="Recent Scans")
    table.add_column("ID", justify="right")
    table.add_column("URL")
    table.add_column("Date")
    for s in scans:
        table.add_row(str(s[0]), s[1], s[2])
    console.print(table)
    scan_id = Prompt.ask("Enter scan ID to analyze", default="")
    if not scan_id.isdigit():
        console.print("[red]Invalid ID.[/red]")
        return
    scan = db.get_scan(int(scan_id))
    if not scan:
        console.print("[red]Scan not found.[/red]")
        return
    console.print("[cyan]Sending vulnerabilities to AI for analysis...[/cyan]")
    try:
        vulnerabilities = db.get_vulnerabilities_for_scan(int(scan_id))
        ai_response = analyze_vulnerabilities(scan['url'], vulnerabilities, config)
        console.print(Panel(ai_response, title="AI Analysis"))
        db.insert_analysis(int(scan_id), ai_response)
        console.print("[green]Analysis saved.[/green]")
    except Exception as e:
        console.print(f"[red]AI analysis failed: {e}[/red]")


def edit_prompt():
    """Open the custom prompt file in the default editor."""
    custom_prompt = Path(config.config.get('custom_prompt_file', 'prompts/custom.prompt'))
    custom_prompt.parent.mkdir(exist_ok=True)
    if not custom_prompt.exists():
        # Copy default if it doesn't exist
        default_prompt = Path(config.config.get('prompt_file', 'prompts/default_analysis.prompt'))
        if default_prompt.exists():
            custom_prompt.write_text(default_prompt.read_text())
    editor = os.environ.get('EDITOR', 'nano')
    console.print(f"[cyan]Opening prompt file with {editor} ...[/cyan]")
    os.system(f"{editor} {custom_prompt}")
    console.print("[green]Prompt file updated.[/green]")


def settings_menu():
    """Settings submenu."""
    while True:
        console.print(Panel("Settings", border_style="blue"))
        console.print("1. Set API Key")
        console.print("2. Toggle AI Provider (google/openai_compatible)")
        console.print("3. Set Concurrency")
        console.print("4. Set Timeout (seconds)")
        console.print("5. Set User-Agent")
        console.print("6. Back to Main Menu")
        choice = Prompt.ask("Select option", choices=["1","2","3","4","5","6"], default="6")
        if choice == "1":
            key = pt_prompt("Enter API key (leave empty to remove): ")
            config.set('api_key', key)
            config.save()
            console.print("[green]API key updated.[/green]")
        elif choice == "2":
            current = config.get('ai_provider', 'google')
            new = 'openai_compatible' if current == 'google' else 'google'
            config.set('ai_provider', new)
            config.save()
            console.print(f"[green]Provider changed to {new}.[/green]")
        elif choice == "3":
            concurrency = Prompt.ask("Concurrency (1-50)", default=str(config.get('concurrency', 10)))
            config.set('concurrency', int(concurrency))
            config.save()
        elif choice == "4":
            timeout = Prompt.ask("Timeout in seconds", default=str(config.get('timeout', 15)))
            config.set('timeout', float(timeout))
            config.save()
        elif choice == "5":
            ua = pt_prompt("User-Agent: ", default=config.get('user_agent', 'AIVWF/1.0'))
            config.set('user_agent', ua)
            config.save()
        elif choice == "6":
            break


def view_history():
    """Show scan history from database."""
    scans = db.get_all_scans(limit=50)
    if not scans:
        console.print("[yellow]No history.[/yellow]")
        return
    table = Table(title="Scan History")
    table.add_column("ID")
    table.add_column("URL")
    table.add_column("Timestamp")
    table.add_column("Vulnerabilities")
    for s in scans:
        count = len(db.get_vulnerabilities_for_scan(s[0]))
        table.add_row(str(s[0]), s[1], s[2], str(count))
    console.print(table)


def export_menu():
    """Export reports."""
    scans = db.get_all_scans(limit=20)
    if not scans:
        console.print("[yellow]No data to export.[/yellow]")
        return
    table = Table(title="Select Scan to Export")
    table.add_column("ID")
    table.add_column("URL")
    for s in scans:
        table.add_row(str(s[0]), s[1])
    console.print(table)
    scan_id = Prompt.ask("Scan ID", default="")
    if not scan_id.isdigit():
        return
    fmt = Prompt.ask("Format", choices=["json","csv","html"], default="html")
    filename = f"report_scan_{scan_id}.{fmt}"
    export_report(int(scan_id), fmt, filename, db)
    console.print(f"[green]Report saved to {filename}[/green]")


def main():
    setup_logging()
    print_banner()
    config.initialize()   # creates config if not exists, prompts for API key

    menu_options = {
        "1": ("Scan a single URL", single_scan),
        "2": ("Bulk scan from file", bulk_scan_menu),
        "3": ("AI analysis of previous scan", ai_analysis_menu),
        "4": ("Edit scan prompt", edit_prompt),
        "5": ("Settings", settings_menu),
        "6": ("View scan history", view_history),
        "7": ("Export report", export_menu),
        "8": ("Exit", lambda: sys.exit(0))
    }

    while True:
        console.print(Panel("AIVWF – Main Menu", border_style="magenta"))
        for key, (desc, _) in menu_options.items():
            console.print(f"[bold]{key}[/bold]. {desc}")
        try:
            choice = Prompt.ask("Choose an option", choices=list(menu_options.keys()), default="8")
            menu_options[choice][1]()
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Exiting...[/yellow]")
            sys.exit(0)
        except Exception as e:
            console.print(f"[red]Unhandled error: {e}[/red]")
            traceback.print_exc()


if __name__ == "__main__":
    main()
