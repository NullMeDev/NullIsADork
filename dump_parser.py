"""
Dump Parser v1.0 — Post-Dump Intelligence Extraction

Standalone module that can:
1. Parse CSV/JSON dump files from sqlmap, ghauri, or our own dumper
2. Extract high-value data: cards, creds, keys, PII, hashes
3. Generate combo lists (user:pass, email:pass)
4. Identify hash types with cracking hints
5. Generate formatted reports
6. Can be used standalone or integrated into the pipeline

Usage standalone:
    python dump_parser.py /path/to/dump.csv
    python dump_parser.py /path/to/sqlmap/output/target/dump/
"""

import re
import os
import sys
import csv
import json
import glob
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger


# Import hash patterns and value patterns from auto_dumper
try:
    from auto_dumper import (
        HASH_PATTERNS, DEEP_VALUE_PATTERNS, EMAIL_PATTERN, PHONE_PATTERN,
        SSN_PATTERN, PASSWORD_COLUMNS, USERNAME_COLUMNS, EMAIL_COLUMNS,
    )
except ImportError:
    # Fallback definitions if running standalone
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    PHONE_PATTERN = re.compile(r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}')
    SSN_PATTERN = re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b')
    PASSWORD_COLUMNS = {
        'password', 'passwd', 'pass', 'pwd', 'user_pass', 'user_password',
        'hashed_password', 'password_hash', 'hash', 'passhash', 'encrypted_password',
    }
    USERNAME_COLUMNS = {
        'username', 'user', 'login', 'user_login', 'user_name', 'name', 'account',
    }
    EMAIL_COLUMNS = {
        'email', 'user_email', 'mail', 'email_address', 'e_mail',
    }
    HASH_PATTERNS = [
        (re.compile(r'^\$2[aby]?\$\d{2}\$[A-Za-z0-9./]{53}$'), "bcrypt", 192, "hashcat -m 3200"),
        (re.compile(r'^\$P\$[A-Za-z0-9./]{31}$'), "phpass/WordPress", 128, "hashcat -m 400"),
        (re.compile(r'^[a-f0-9]{32}$'), "MD5", 128, "hashcat -m 0"),
        (re.compile(r'^[a-f0-9]{40}$'), "SHA1", 160, "hashcat -m 100"),
        (re.compile(r'^[a-f0-9]{64}$'), "SHA256", 256, "hashcat -m 1400"),
        (re.compile(r'^\*[A-F0-9]{40}$', re.I), "MySQL 4.1+", 160, "hashcat -m 300"),
    ]
    DEEP_VALUE_PATTERNS = [
        (re.compile(r'sk_live_[A-Za-z0-9]{20,}'), "stripe_secret_key"),
        (re.compile(r'pk_live_[A-Za-z0-9]{20,}'), "stripe_publishable_key"),
        (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key"),
        (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "jwt_token"),
        (re.compile(r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}'), "mongodb_uri"),
    ]


@dataclass
class ParseReport:
    """Results from parsing dump files."""
    source_files: List[str] = field(default_factory=list)
    total_rows: int = 0
    
    # High-value data
    cards: List[Dict] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)
    
    # PII
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    ssns: Set[str] = field(default_factory=set)
    
    # Hashes
    hashes: List[Dict] = field(default_factory=list)
    
    # Combos
    combos_user_pass: List[str] = field(default_factory=list)
    combos_email_pass: List[str] = field(default_factory=list)


# Card number columns
CARD_COLUMNS = {
    'card', 'card_number', 'cardnumber', 'cc', 'cc_number', 'pan',
    'credit_card', 'creditcard', 'card_num', 'ccnum', 'account_number',
}
CVV_COLUMNS = {'cvv', 'cvc', 'cvv2', 'csc', 'security_code', 'card_code'}
EXPIRY_COLUMNS = {'expiry', 'exp', 'expiration', 'exp_date', 'card_exp', 'exp_month', 'exp_year'}


class DumpParser:
    """Parse external dump files and extract intelligence."""

    def __init__(self):
        pass

    def parse_file(self, filepath: str) -> ParseReport:
        """Parse a single dump file (CSV or JSON)."""
        report = ParseReport()
        filepath = str(filepath)
        
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return report
        
        report.source_files.append(filepath)
        
        if filepath.endswith('.csv'):
            rows = self._read_csv(filepath)
        elif filepath.endswith('.json'):
            rows = self._read_json(filepath)
        else:
            # Try CSV first, then JSON
            rows = self._read_csv(filepath) or self._read_json(filepath) or []
        
        report.total_rows = len(rows)
        self._extract_from_rows(rows, report)
        return report

    def parse_directory(self, dirpath: str) -> ParseReport:
        """
        Parse all dump files in a directory.
        Handles sqlmap output structure: dump/database_name/table.csv
        """
        report = ParseReport()
        dirpath = str(dirpath)
        
        # Find all CSV and JSON files
        patterns = ['**/*.csv', '**/*.json', '**/*.txt']
        files = []
        for pattern in patterns:
            files.extend(glob.glob(os.path.join(dirpath, pattern), recursive=True))
        
        if not files:
            logger.warning(f"No dump files found in {dirpath}")
            return report
        
        logger.info(f"Found {len(files)} dump files in {dirpath}")
        
        for filepath in sorted(files):
            if os.path.getsize(filepath) == 0:
                continue
            
            file_report = self.parse_file(filepath)
            
            # Merge into main report
            report.source_files.extend(file_report.source_files)
            report.total_rows += file_report.total_rows
            report.cards.extend(file_report.cards)
            report.credentials.extend(file_report.credentials)
            report.secrets.extend(file_report.secrets)
            report.emails.update(file_report.emails)
            report.phones.update(file_report.phones)
            report.ssns.update(file_report.ssns)
            report.hashes.extend(file_report.hashes)
            report.combos_user_pass.extend(file_report.combos_user_pass)
            report.combos_email_pass.extend(file_report.combos_email_pass)
        
        return report

    def parse_sqlmap_output(self, sqlmap_dir: str) -> ParseReport:
        """
        Parse sqlmap output directory structure:
        ~/.sqlmap/output/target.com/dump/database_name/table.csv
        """
        dump_dir = os.path.join(sqlmap_dir, 'dump')
        if os.path.exists(dump_dir):
            return self.parse_directory(dump_dir)
        return self.parse_directory(sqlmap_dir)

    # ──────────────────────────────────────────────────────────
    # File readers
    # ──────────────────────────────────────────────────────────

    def _read_csv(self, filepath: str) -> List[Dict]:
        """Read CSV file into list of dicts."""
        rows = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                # Detect delimiter
                sample = f.read(4096)
                f.seek(0)
                
                if '\t' in sample and ',' not in sample:
                    delimiter = '\t'
                elif ';' in sample and ',' not in sample:
                    delimiter = ';'
                else:
                    delimiter = ','
                
                reader = csv.DictReader(f, delimiter=delimiter)
                for row in reader:
                    rows.append(dict(row))
        except Exception as e:
            logger.debug(f"CSV read error {filepath}: {e}")
        return rows

    def _read_json(self, filepath: str) -> List[Dict]:
        """Read JSON file into list of dicts."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
            elif isinstance(data, dict):
                # Check for nested data structures
                for key in ('data', 'rows', 'results', 'entries', 'cards',
                           'credentials', 'users', 'records'):
                    if key in data and isinstance(data[key], list):
                        return [d for d in data[key] if isinstance(d, dict)]
                return [data]
        except Exception as e:
            logger.debug(f"JSON read error {filepath}: {e}")
        return []

    # ──────────────────────────────────────────────────────────
    # Extraction
    # ──────────────────────────────────────────────────────────

    def _extract_from_rows(self, rows: List[Dict], report: ParseReport):
        """Extract all intelligence from rows."""
        for row in rows:
            card_entry = {}
            cred_entry = {}
            username = None
            email = None
            password = None
            
            for col, val in row.items():
                if not val or not col:
                    continue
                val_str = str(val).strip()
                if val_str.lower() in ('null', 'none', '', 'n/a'):
                    continue
                
                col_lower = (col or '').lower().strip()
                
                # ── Card data ──
                if col_lower in CARD_COLUMNS:
                    clean = val_str.replace(' ', '').replace('-', '')
                    if re.match(r'^[3-6]\d{12,18}$', clean):
                        card_entry['number'] = val_str
                elif col_lower in CVV_COLUMNS:
                    if re.match(r'^\d{3,4}$', val_str):
                        card_entry['cvv'] = val_str
                elif col_lower in EXPIRY_COLUMNS:
                    card_entry['expiry'] = val_str
                
                # ── Credentials ──
                if col_lower in USERNAME_COLUMNS:
                    username = val_str
                    cred_entry['username'] = val_str
                if col_lower in EMAIL_COLUMNS:
                    email = val_str
                    cred_entry['email'] = val_str
                if col_lower in PASSWORD_COLUMNS:
                    password = val_str
                    cred_entry['password'] = val_str
                    
                    # Hash identification
                    hash_type = self._identify_hash(val_str)
                    if hash_type:
                        report.hashes.append({
                            "hash": val_str[:80],
                            "type": hash_type[0],
                            "crack_hint": hash_type[1],
                            "column": col,
                        })
                
                # ── Deep secret scan on cell values ──
                for pattern, secret_type in DEEP_VALUE_PATTERNS:
                    match = pattern.search(val_str)
                    if match:
                        report.secrets.append({
                            "type": secret_type,
                            "value": match.group(),
                            "column": col,
                        })
                
                # ── PII ──
                for em in EMAIL_PATTERN.findall(val_str):
                    if not em.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
                        report.emails.add(em.lower())
                for phone in PHONE_PATTERN.findall(val_str):
                    digits = re.sub(r'\D', '', phone)
                    if 10 <= len(digits) <= 11:
                        report.phones.add(phone)
                for ssn in SSN_PATTERN.findall(val_str):
                    digits = re.sub(r'\D', '', ssn)
                    if len(digits) == 9 and not digits.startswith('000'):
                        report.ssns.add(ssn)
            
            if card_entry.get('number'):
                report.cards.append(card_entry)
            if cred_entry.get('password') or (cred_entry.get('username') and cred_entry.get('email')):
                report.credentials.append(cred_entry)
            
            # Combo list generation
            if password:
                if username:
                    report.combos_user_pass.append(f"{username}:{password}")
                if email:
                    report.combos_email_pass.append(f"{email}:{password}")

    def _identify_hash(self, value: str) -> Optional[Tuple[str, str]]:
        """Identify hash type."""
        value = value.strip()
        if len(value) < 8 or len(value) > 200:
            return None
        for pattern, hash_type, _, crack_hint in HASH_PATTERNS:
            if pattern.match(value):
                return (hash_type, crack_hint)
        return None

    # ──────────────────────────────────────────────────────────
    # Report generation
    # ──────────────────────────────────────────────────────────

    def generate_report(self, report: ParseReport) -> str:
        """Generate formatted text report."""
        lines = [
            "=" * 60,
            "📦 DUMP PARSER INTELLIGENCE REPORT",
            f"⏰ {datetime.now().isoformat()}",
            f"📂 Sources: {len(report.source_files)} files, {report.total_rows} rows",
            "=" * 60,
            "",
        ]
        
        if report.cards:
            lines.append(f"💳 CARDS: {len(report.cards)}")
            for c in report.cards[:10]:
                lines.append(f"  {c.get('number', '?')} | CVV: {c.get('cvv', '?')} | "
                           f"Exp: {c.get('expiry', '?')}")
            if len(report.cards) > 10:
                lines.append(f"  ... +{len(report.cards) - 10} more")
            lines.append("")
        
        if report.credentials:
            lines.append(f"🔓 CREDENTIALS: {len(report.credentials)}")
            for c in report.credentials[:10]:
                lines.append(f"  {c.get('username', c.get('email', '?'))}:{c.get('password', '?')}")
            if len(report.credentials) > 10:
                lines.append(f"  ... +{len(report.credentials) - 10} more")
            lines.append("")
        
        if report.secrets:
            lines.append(f"🔐 EMBEDDED SECRETS: {len(report.secrets)}")
            by_type = {}
            for s in report.secrets:
                t = s['type']
                by_type[t] = by_type.get(t, 0) + 1
            for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
                lines.append(f"  {t}: {n}")
            lines.append("")
        
        if report.hashes:
            lines.append(f"#️⃣ PASSWORD HASHES: {len(report.hashes)}")
            by_type = {}
            for h in report.hashes:
                t = h['type']
                if t not in by_type:
                    by_type[t] = {"count": 0, "hint": h['crack_hint']}
                by_type[t]["count"] += 1
            for t, info in by_type.items():
                lines.append(f"  {t}: {info['count']} → {info['hint']}")
            lines.append("")
        
        if report.emails:
            lines.append(f"📧 EMAILS: {len(report.emails)}")
        if report.phones:
            lines.append(f"📱 PHONES: {len(report.phones)}")
        if report.ssns:
            lines.append(f"🆔 SSNs: {len(report.ssns)}")
        
        if report.combos_email_pass:
            lines.append(f"\n📝 EMAIL:PASS COMBOS: {len(report.combos_email_pass)}")
            for c in report.combos_email_pass[:5]:
                lines.append(f"  {c}")
        if report.combos_user_pass:
            lines.append(f"📝 USER:PASS COMBOS: {len(report.combos_user_pass)}")
        
        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    def save_outputs(self, report: ParseReport, output_dir: str):
        """Save parsed outputs to files."""
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if report.combos_email_pass:
            with open(os.path.join(output_dir, f"combo_emailpass_{ts}.txt"), 'w') as f:
                f.write('\n'.join(sorted(set(report.combos_email_pass))))
        
        if report.combos_user_pass:
            with open(os.path.join(output_dir, f"combo_userpass_{ts}.txt"), 'w') as f:
                f.write('\n'.join(sorted(set(report.combos_user_pass))))
        
        if report.hashes:
            with open(os.path.join(output_dir, f"hashes_{ts}.txt"), 'w') as f:
                by_type = {}
                for h in report.hashes:
                    t = h['type']
                    if t not in by_type:
                        by_type[t] = []
                    by_type[t].append(h['hash'])
                for ht, hashes in by_type.items():
                    f.write(f"# {ht} ({len(hashes)} hashes)\n")
                    f.write('\n'.join(hashes) + '\n\n')
        
        if report.emails:
            with open(os.path.join(output_dir, f"emails_{ts}.txt"), 'w') as f:
                f.write('\n'.join(sorted(report.emails)))
        
        if report.cards:
            with open(os.path.join(output_dir, f"cards_{ts}.json"), 'w') as f:
                json.dump(report.cards, f, indent=2)
        
        if report.secrets:
            with open(os.path.join(output_dir, f"secrets_{ts}.json"), 'w') as f:
                json.dump(report.secrets, f, indent=2)
        
        # Full JSON report
        with open(os.path.join(output_dir, f"full_report_{ts}.json"), 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total_rows": report.total_rows,
                "cards": report.cards,
                "credentials": report.credentials,
                "secrets": report.secrets,
                "emails": sorted(report.emails),
                "phones": sorted(report.phones),
                "ssns": sorted(report.ssns),
                "hashes": report.hashes,
                "combos_user_pass": len(report.combos_user_pass),
                "combos_email_pass": len(report.combos_email_pass),
            }, f, indent=2)
        
        logger.info(f"[DumpParser] Saved outputs to {output_dir}")


# ──────────────────────────────────────────────────────────────
# CLI usage
# ──────────────────────────────────────────────────────────────

def main():
    """CLI entry point for standalone dump parsing."""
    if len(sys.argv) < 2:
        print("Usage: python dump_parser.py <file_or_directory> [output_dir]")
        print("  Parses CSV/JSON dump files and extracts cards, creds, keys, hashes, PII")
        print("\nExamples:")
        print("  python dump_parser.py dump.csv")
        print("  python dump_parser.py ~/.sqlmap/output/target.com/")
        print("  python dump_parser.py /path/to/dumps/ /path/to/output/")
        sys.exit(1)
    
    target = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "parsed_output"
    
    parser = DumpParser()
    
    if os.path.isfile(target):
        report = parser.parse_file(target)
    elif os.path.isdir(target):
        # Check if it's sqlmap output
        if os.path.exists(os.path.join(target, 'dump')):
            report = parser.parse_sqlmap_output(target)
        else:
            report = parser.parse_directory(target)
    else:
        print(f"Error: {target} not found")
        sys.exit(1)
    
    # Print report
    print(parser.generate_report(report))
    
    # Save outputs
    parser.save_outputs(report, output_dir)
    print(f"\nOutputs saved to: {output_dir}/")


if __name__ == "__main__":
    main()
