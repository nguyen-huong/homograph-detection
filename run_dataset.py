import csv
import sys
from collections import defaultdict
from pathlib import Path
from shannon import analyze_url

BASE_PATH = " "
DATASET_PATH = " "
OUTPUT_PATH = " "


FAMILIES = {'legitimate', 'script', 'digit', 'keyboard', 'multichar', 'nkfc', 'punycode', 'unicode', 'ligature'}
SCRIPT_NAMES = {'cyrillic', 'greek', 'arabic', 'armenian', 'hebrew', 'georgian', 'thai', 'lao', 'hangul', 'higragana', 'katakana', 'han', 'cherokee', 'ethiopic', 'devangari', 'bengali', 'tamil', 'telugu', 'kannada', 'malayalam', 'gujarati', 'gurmukhi', 'oriya', 'myanmar', 'syriac'}
MECHANISM_MAP = {'multiscript':'multiscript',
                 'single_foreign': 'single_foreign',
                 'digit substitution': 'digit substitution',
                 'multicharacter': 'multicharacter',
                 'keyboard': 'keyboard',
                 'ligature': 'ligature',
                 'nkfc': 'nkfc',
                 'punycode': 'punycode',
                 'unicode': 'unicode'

                 }

def normalize_family(family, mechanism):
    family = (family or "").lower()
    mech = (mechanism or "").lower()
    for script in SCRIPT_NAMES:
        if script in mech:
            return f"script_{script}"
    for keyword, category in MECHANISM_MAP.items():
        if keyword in mech:
            return category

    if family in FAMILIES:
        return family
    if family:
        return family
    return 'Unknown'


def main():
    stats = {'read':0, 'written':0, 'skipped':0, 'bad_rows':0}
    counts = {'original': defaultdict(int), 'normalized': defaultdict(int), 'mechanism': defaultdict(int)}
    headers = [ 'url', 'label', 'original_family', 'normalized_family', 'mechanism','entropy', 'script_entropy', 'rarity', 'nonascii_count', 'nonascii_ratio']
    with open(DATASET_PATH, newline='', encoding='utf=8') as csvfile:
        reader = csv.DictReader(csvfile)
        with open(OUTPUT_PATH, 'w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=headers)
            writer.writerheader()
            for row in reader:
                stats['read'] +=1
                try: 
                    url=(row.get('domain') or row.get('url') or '').strip()
                    label=(row.get('label') or '').strip()
                    original_family= (row.get('original_family') or row.get('family') or (row.get('normalized_family') or row.get('source_domain') or '')).strip()
                    mechanism = (row.get('mechanism') or '').strip()
                    normalized_family = normalized_family(original_family, mechanism)
                    if not url:
                        stats['skipped'] += 1
                        continue
                    entropy, script_entropy, rarity, _, _, _, nonascii_count, nonascii_ratio = analyze_url(url)
                    counts['original'][original_family] += 1
                    counts['normalized'][normalized_family] += 1
                    counts['mechanism'][mechanism] += 1
                    result_row = {
                        'url': url,
                        'label': label,
                        'original_family': original_family,
                        'normalized_family': normalized_family,
                        'mechanism': mechanism,
                        'entropy': f"{entropy:.6f}",
                        'script_entropy': f"{script_entropy:.6f}",
                        'rarity': f"{rarity:.6f}",
                        'nonascii_count': nonascii_count, 
                        'nonascii_ratio': f"{nonascii_ratio:.6f}"
                    }
                    writer.writerow(result_row)
                    stats['written'] += 1
                except Exception as exc:
                    stats['bad_rows'] += 1
                    continue

if __name__ == "__main__":
    main()
