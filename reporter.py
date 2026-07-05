"""
Export scan results to JSON, CSV, or HTML using Jinja2.
"""
import json
import csv
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from database import Database

TEMPLATE_DIR = Path('templates')

def export_report(scan_id: int, fmt: str, filename: str, db: Database):
    scan = db.get_scan(scan_id)
    if not scan:
        raise ValueError("Scan not found")
    vulnerabilities = db.get_vulnerabilities_for_scan(scan_id)
    analysis_rows = db.conn.execute("SELECT ai_response FROM analysis WHERE scan_id=?", (scan_id,)).fetchall()
    ai_response = analysis_rows[0]['ai_response'] if analysis_rows else ''

    if fmt == 'json':
        with open(filename, 'w') as f:
            json.dump({
                'scan': scan,
                'vulnerabilities': vulnerabilities,
                'ai_analysis': ai_response
            }, f, indent=2)
    elif fmt == 'csv':
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Payload', 'Evidence'])
            for v in vulnerabilities:
                writer.writerow([v['type'], v.get('payload', ''), v.get('evidence', '')])
    elif fmt == 'html':
        env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
        template = env.get_template('report.html')
        html = template.render(
            url=scan['url'],
            timestamp=scan['timestamp'],
            vulnerabilities=vulnerabilities,
            ai_response=ai_response
        )
        with open(filename, 'w') as f:
            f.write(html)
