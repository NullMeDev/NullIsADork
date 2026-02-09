#!/usr/bin/env python3
"""
Convert raw custom dorks into proper search-engine operator format.

Input format examples:
  Credit card? ".com"                          → "Credit card" site:.com
  "Credit card" / .com..php?id=                → inurl:".php?id=" "Credit card" site:.com
  ..php? "Credit card" / .com id=              → inurl:".php?id=" "Credit card" site:.com
  Credit card..php?id=                         → inurl:".php?id=" "Credit card"
  Credit card / php?id=                        → inurl:"php?id=" "Credit card"
  payjp / php?token=                           → inurl:"php?token=" "payjp"

Preserves all keywords, TLDs, extensions, and parameters — only restructures with operators.
"""

import re
import sys
from pathlib import Path


# Known TLDs (dot-prefixed) to detect site: targets
TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil',
    '.co.uk', '.com.au', '.ca', '.de', '.fr', '.es', '.it', '.nl', '.be', '.ch',
    '.at', '.se', '.no', '.dk', '.fi', '.pl', '.cz', '.ru', '.in', '.br', '.mx',
    '.ar', '.cl', '.co', '.za', '.nz', '.ie', '.pt', '.gr', '.tr', '.jp', '.kr',
    '.cn', '.tw', '.hk', '.sg', '.my', '.th', '.ph', '.ae', '.sa', '.il', '.pk',
    '.ng', '.ke', '.gh', '.tz', '.ug', '.rw', '.io', '.me', '.info', '.biz',
    '.us', '.uk', '.eu', '.asia', '.shop', '.store', '.online', '.site', '.xyz',
    '.tech', '.app', '.dev', '.cloud', '.pro', '.solutions', '.services', '.agency',
    '.digital', '.media', '.studio', '.design', '.academy', '.institute', '.foundation',
    '.church', '.charity', '.ngo', '.coop', '.museum',
}

# Web extensions
EXTENSIONS = {
    '.php', '.asp', '.aspx', '.jsp', '.cfm', '.cgi', '.pl', '.do', '.action',
    '.htm', '.html', '.shtml', '.nsf', '.xhtml', '.jspx', '.py', '.rb',
    '.php3', '.php4', '.php5', '.phtml', '.jsf', '.ashx', '.asmx', '.json', '.xml',
}


def extract_quoted_strings(text):
    """Extract all quoted strings from text, return them and the remaining text."""
    quoted = re.findall(r'"([^"]*)"', text)
    remaining = re.sub(r'"[^"]*"', ' ', text)
    return quoted, remaining


def find_tld(text):
    """Find a TLD in the text. Returns (tld, remaining_text) or (None, text)."""
    # Check for compound TLDs first (e.g., .co.uk, .com.au)
    for tld in sorted(TLDS, key=len, reverse=True):
        # Match TLD that appears as a discrete token
        pattern = re.escape(tld) + r'(?=\s|$|\.\.|\?|/)'
        m = re.search(pattern, text)
        if m:
            remaining = text[:m.start()] + text[m.end():]
            return tld, remaining
    return None, text


def find_extension_and_param(text):
    """Find extension..ext?param= or ext?param= patterns. Returns (ext_param, remaining) or (None, text)."""
    # Pattern: ..ext?param= or .ext?param= (with optional leading dots)
    m = re.search(r'\.{0,2}(\.\w+\?[\w_#=]+)', text)
    if m:
        ext_param = m.group(1)
        remaining = text[:m.start()] + text[m.end():]
        return ext_param, remaining
    
    # Pattern: ext?param= (no leading dot, like php?id=)
    m = re.search(r'(?:^|\s|/)(\w+\?[\w_#=]+)', text)
    if m:
        candidate = m.group(1)
        # Only match if starts with known extension name
        ext_name = '.' + candidate.split('?')[0]
        if ext_name in EXTENSIONS:
            remaining = text[:m.start()] + text[m.end():]
            return '.' + candidate, remaining  # Normalize to .ext?param=
    
    return None, text


def find_standalone_param(text):
    """Find standalone parameter like 'id=' at end of line."""
    m = re.search(r'\b(\w+=)\s*$', text.strip())
    if m:
        return m.group(1), text[:text.rfind(m.group(1))].strip()
    return None, text


def clean_keyword(text):
    """Clean up a keyword string — remove operators, normalize whitespace."""
    # Remove / separators, ?, leading/trailing dots
    text = text.strip()
    text = re.sub(r'\s*/\s*', ' ', text)
    text = text.replace('?', ' ')
    text = re.sub(r'^\.+', '', text)
    text = re.sub(r'\.+$', '', text)
    text = re.sub(r'\s+', ' ', text)
    text = text.strip(' ./')
    return text


def is_comment_or_section_header(line):
    """Check if line is a comment or section header fragment."""
    stripped = line.strip()
    if stripped.startswith('#'):
        return True
    # Lines that are ONLY section markers like "# === SOMETHING ==="
    if re.match(r'^#\s*={2,}', stripped):
        return True
    return False


def strip_inline_comments(text):
    """Remove inline # === ... ==== fragments from dork text."""
    return re.sub(r'#\s*={2,}[^=]*={2,}', '', text).strip()


def convert_dork(raw_line):
    """Convert a single raw dork line to operator format.
    
    Returns converted dork string, or None if line should be skipped.
    """
    line = raw_line.strip()
    
    # Skip empty lines and pure comments
    if not line or line.startswith('#'):
        return None
    
    # Strip inline comment fragments like "# === PAYMENT / ORDER PARAMS ===="
    line = strip_inline_comments(line)
    if not line:
        return None
    
    # Extract all quoted strings first
    quoted_strings, remaining = extract_quoted_strings(line)
    
    # Filter out section-header-like quoted strings
    keywords_quoted = []
    for qs in quoted_strings:
        if re.match(r'^#?\s*={2,}', qs) or qs.startswith('# '):
            continue  # Skip "# === SOMETHING ===" in quotes
        keywords_quoted.append(qs)
    
    # Find TLD in the remaining text
    tld, remaining = find_tld(remaining)
    
    # If TLD was inside a quoted string, check there too
    if tld is None:
        for i, qs in enumerate(keywords_quoted):
            for t in sorted(TLDS, key=len, reverse=True):
                if t in qs and len(qs.strip()) == len(t):
                    tld = t
                    keywords_quoted.pop(i)
                    break
            if tld:
                break
    
    # Find extension+param pattern (e.g., .php?id= or ..php?id=)
    ext_param, remaining = find_extension_and_param(remaining)
    
    # If no ext_param yet, check if there's a standalone param after removing other parts
    standalone_param = None
    if ext_param is None:
        standalone_param, remaining = find_standalone_param(remaining)
    
    # Also check original remaining for extension without param
    # Pattern like: ..php? at start means extension is separate from param
    if ext_param is None and standalone_param:
        m = re.search(r'\.{0,2}(\.\w+)\?', line)
        if m:
            ext_name = m.group(1)
            if ext_name in EXTENSIONS:
                ext_param = ext_name + '?' + standalone_param
                standalone_param = None
    
    # Clean up remaining text to extract unquoted keywords
    remaining = clean_keyword(remaining)
    
    # Build set of extension base names to filter out (php, asp, htm, etc.)
    ext_basenames = {e.lstrip('.') for e in EXTENSIONS}
    # Also filter out TLD-like strings
    tld_strings = {t.lstrip('.') for t in TLDS}
    noise_keywords = ext_basenames | tld_strings | {
        '/', '?', '.', '..', '...', '=', '-', '(', ')', 
        'php', 'asp', 'aspx', 'jsp', 'cfm', 'cgi', 'htm', 'html',
        'xml', 'json', 'shtml', 'nsf', 'xhtml', 'jspx', 'jsf',
        'ashx', 'asmx', 'phtml', 'php3', 'php4', 'php5', 'pl',
        'py', 'rb', 'do', 'action',
    }
    
    # Combine all keyword parts
    all_keywords = []
    for kw in keywords_quoted:
        kw = kw.strip()
        # Skip empty, single-char, extension names, TLDs, and noise
        if not kw or len(kw) <= 1:
            continue
        if kw.lower() in noise_keywords:
            continue
        if kw.startswith('.') and kw in TLDS:
            continue
        all_keywords.append(f'"{kw}"')
    
    # Add unquoted keywords from remaining
    if remaining:
        words = remaining.split()
        # Filter out noise tokens — extensions, TLDs, single chars
        words = [w for w in words if w.lower() not in noise_keywords and len(w) > 1 and not w.startswith('.')]
        if words:
            phrase = ' '.join(words)
            if phrase and not phrase.startswith('.'):
                all_keywords.append(f'"{phrase}"')
    
    # Skip if we ended up with nothing meaningful
    if not all_keywords and not ext_param and not tld:
        return None
    
    # Build the converted dork
    parts = []
    
    # 1. inurl: for extension+parameter targeting
    if ext_param:
        # Normalize: ensure it starts with .
        if not ext_param.startswith('.'):
            ext_param = '.' + ext_param
        parts.append(f'inurl:"{ext_param}"')
    
    # 2. Keywords
    parts.extend(all_keywords)
    
    # 3. site: for TLD targeting
    if tld:
        parts.append(f'site:*{tld}')
    
    result = ' '.join(parts)
    
    # Final cleanup
    result = re.sub(r'\s+', ' ', result).strip()
    
    # Skip if result is too short or just an operator
    if len(result) < 10:
        return None
    
    return result


def main():
    input_file = Path(__file__).parent / "params" / "custom_dorks_raw.txt"
    output_file = Path(__file__).parent / "params" / "custom_dorks.txt"
    
    if not input_file.exists():
        print(f"ERROR: {input_file} not found")
        sys.exit(1)
    
    print(f"Reading {input_file}...")
    
    converted = set()
    skipped = 0
    total = 0
    errors = 0
    
    with open(input_file, "r", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            total += 1
            try:
                result = convert_dork(line)
                if result:
                    converted.add(result)
                else:
                    skipped += 1
            except Exception as e:
                errors += 1
                if errors <= 10:
                    print(f"  Error on line {line_num}: {e}")
                    print(f"    Raw: {line.strip()[:100]}")
    
    # Sort for consistent output
    sorted_dorks = sorted(converted)
    
    print(f"\nResults:")
    print(f"  Total raw lines:    {total:,}")
    print(f"  Skipped/empty:      {skipped:,}")
    print(f"  Errors:             {errors:,}")
    print(f"  Unique dorks:       {len(sorted_dorks):,}")
    print(f"  Dedup removed:      {total - skipped - errors - len(sorted_dorks):,}")
    
    # Write output
    with open(output_file, "w") as f:
        f.write(f"# Custom dorks — converted from {total:,} raw entries\n")
        f.write(f"# Unique dorks: {len(sorted_dorks):,}\n")
        f.write(f"# Format: operator-based search queries for DDG/Bing/Startpage/Brave\n\n")
        for dork in sorted_dorks:
            f.write(dork + "\n")
    
    print(f"\nWritten to {output_file}")
    
    # Show samples
    print(f"\nSample converted dorks:")
    import random
    samples = random.sample(sorted_dorks, min(20, len(sorted_dorks)))
    for s in samples:
        print(f"  {s}")


if __name__ == "__main__":
    main()
