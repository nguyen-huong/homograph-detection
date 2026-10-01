import csv
import os
import sys
from collections import defaultdict

# Author: Nguyen, Huong
# Last Updated: Aug 2026
# Description: Loadd 500k composite homograph URLs, evaluate suspiciousness based on raw entropy, script entropy, and rarity. 50k email spoof attacks, 50k digit substitution, 50k invisible char, 50k multichar, 50k foreign script, 50k punycode. 250k legit.

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
# 500k url, glyphnet

INPUT_FILES = ['datasets.csv']
# 95th p95, metric only 5% legit URLs exceed these
SCRIPT_THRESHOLD = 0.7219
ENTROPY_THRESHOLD = 3.9292
RARITY_THRESHOLD = 0.7053
# catch non composite homograph URLs like digit_substitution/multichar/keyboard, work with entropy
LEVENSHTEIN_THRESHOLD = 1


def predict_attack(row):
    # catch impersionation/non-comopsite, then Unicode, then composite
    script_entropy = float(row.get('script_entropy', 0))
    entropy = float(row.get('entropy', 0))
    rarity = float(row.get('rarity', 0))
    raw_entropy = float(row.get('entropy', 0))
    levenshtein = int(row.get('levenshtein', 0))
    family = (
        row.get('normalized_family')
        or row.get('original_family')
        or 'unknown'
    )

    if levenshtein >= 1 and family in {'digit_substitution', 'multicharacter'}:
        return 1
    if script_entropy >= SCRIPT_THRESHOLD:
        return 1
    if raw_entropy >= ENTROPY_THRESHOLD:
        return 1
    if rarity >= RARITY_THRESHOLD:
        return 1
    return 0


def process_file(path, forced_label=None):
    stats = {
        'total': 0,
        'correct': 0,
        'bad_rows': 0,
        'negative_rows': 0,
        'tp': 0,
        'tn': 0,
        'fp': 0,
        'fn': 0,
        'family_stats': defaultdict(
            lambda: {
                'total': 0,
                'correct': 0,
                'tp': 0,
                'tn': 0,
                'fp': 0,
                'fn': 0
            }
        ),
        'mechanism_ranges': {},
    }

    with open(path, 'r', encoding='utf-8-sig', newline='') as file:
        reader = csv.DictReader(file)
        for row in reader:
            try:
                label = (
                    int(row['label'])
                    if forced_label is None
                    else int(forced_label)
                )
                script_entropy = float(row.get('script_entropy', 0))
                family = (row.get('normalized_family') or row.get('original_family') or 'unknown')
                mechanism = row.get('mechanism') or 'unknown'

                prediction = predict_attack(row)
                if label == 0:
                    stats['negative_rows'] += 1

            except Exception:
                stats['bad_rows'] += 1
                continue

            stats['total'] += 1

            if prediction == label:
                stats['correct'] += 1
            if label == 1 and prediction == 1:
                stats['tp'] += 1
            if label == 0 and prediction == 0:
                stats['tn'] += 1
            if label == 0 and prediction == 1:
                stats['fp'] += 1
            if label == 1 and prediction == 0:
                stats['fn'] += 1

            family_stats = stats['family_stats'][family]
            family_stats['total'] += 1
            if label == 1 and prediction == 1:
                family_stats['tp'] += 1
            if label == 0 and prediction == 0:
                family_stats['tn'] += 1
            if label == 0 and prediction == 1:
                family_stats['fp'] += 1
            if label == 1 and prediction == 0:
                family_stats['fn'] += 1

            if mechanism not in stats['mechanism_ranges']:
                stats['mechanism_ranges'][mechanism] = [
                    script_entropy,
                    script_entropy
                ]
            else:
                stats['mechanism_ranges'][mechanism][0] = min(
                    stats['mechanism_ranges'][mechanism][0],
                    script_entropy
                )
                stats['mechanism_ranges'][mechanism][1] = max(
                    stats['mechanism_ranges'][mechanism][1],
                    script_entropy
                )

    return stats


stats = {
    'total': 0,
    'correct': 0,
    'bad_rows': 0,
    'negative_rows': 0,
    'tp': 0,
    'tn': 0,
    'fp': 0,
    'fn': 0,
    'family_stats': defaultdict(
        lambda: {
            'total': 0,
            'correct': 0,
            'tp': 0,
            'tn': 0,
            'fp': 0,
            'fn': 0
        }
    ),
    'mechanism_ranges': {}
}


for path in INPUT_FILES:
    if not os.path.exists(path):
        continue
    file_stats = process_file(
        path,
        forced_label=0 if 'legitimate' in path.lower() else None
    )

    stats['total'] += file_stats['total']
    stats['correct'] += file_stats['correct']
    stats['bad_rows'] += file_stats['bad_rows']
    stats['negative_rows'] += file_stats['negative_rows']
    stats['tp'] += file_stats['tp']
    stats['tn'] += file_stats['tn']
    stats['fp'] += file_stats['fp']
    stats['fn'] += file_stats['fn']

    for family in file_stats['family_stats']:
        agg = stats['family_stats'][family]
        fam = file_stats['family_stats'][family]
        agg['total'] += fam['total']
        agg['correct'] += fam['correct']
        agg['tp'] += fam['tp']
        agg['tn'] += fam['tn']
        agg['fp'] += fam['fp']
        agg['fn'] += fam['fn']

    accuracy = (stats['correct'] / stats['total'] if stats['total'] else 0.0)

    precision = (stats['tp'] / (stats['tp'] + stats['fp']) if (stats['tp'] + stats['fp']) else 0.0)

    recall = (stats['tp'] / (stats['tp'] + stats['fn']) if (stats['tp'] + stats['fn']) else 0.0)

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    for family in sorted(stats['family_stats']):
        family_stats = stats['family_stats'][family]
        family_accuracy = family_stats['correct'] / family_stats['total'] if family_stats['total'] else 0.0
