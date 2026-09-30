# Author: Nguyen, Huong
# Last Updated: Aug 2026
# Description: Identify indicators of suspicious or malicious URLs by scoring unusual Unicode and mixed-script patterns without relying on a URL allowlist for review.
import unicodedata
from urllib.parse import urlsplit
from math import log
from glyph_match import nearest_domain

tests = ()
real = ()
unseen = ()

def script_bucket(char):
    if ord(char) < 128:
        return 'ASCII'
    name=unicodedata.name(char, '')
    if not name:
        return 'Unknown'
    return name.split(' ')[0].lower()


def shannon_entropy(string, script_aware=False):
    if not string:
        return 0.0
    items = [script_bucket(c) for c in string] if script_aware else list(string)
    # frequency of each unique element 
    frequency = {}
    for item in items:
        if item in frequency:
            frequency[item] = frequency.get(item, 0) + 1
        total_elements = len(items)
        entropy = 0.0
        for count in frequency.values():
            p = count / total_elements
            entropy -= p * log(p, 2)
        return entropy

def build_distribution(corpus):
    counts = {}
    total = 0
    for url in corpus:
        for char in url:
            bucket = script_bucket(char)
            counts[bucket] = counts.get(bucket, 0) + 1
            total += 1
    return counts, total

LEGITIMATE_COUNTS, LEGITIMATE_TOTAL = build_distribution(real)

def p_script(bucket, alpha=1.0):
    vocab_size = len(LEGITIMATE_COUNTS) + 1
    count = LEGITIMATE_COUNTS.get(bucket, 0)
    return (count + alpha) / (LEGITIMATE_TOTAL + alpha * vocab_size)

def transformation_rarity(string):
    if not string:
        return 0.0
    rarity = 0.0
    total_elements = len(string)
    for char in string:
        bucket = script_bucket(char)
        p = p_script(bucket)
        rarity += -log(p, 2)
    return rarity

def keyboard_neighbors():
    rows = ("qwertyuiop","asdfghjkl","zxcvbnm")
    neighbors = {c: set() for c in ''.join(rows)}
    for row in rows:
        for i, c in enumerate(row):
            if i > 0:
                neighbors[c].add(row[i-1])
            if i + 1 < len(row):
                neighbors[c].add(row[i+1])
    for upper, middle in zip(rows, rows):
        neighbors[upper].add(middle)
        neighbors[middle].add(upper)
    for middle, lower in zip(rows[1:], rows[2:]):
        for i, c in enumerate(middle):
            if i < len(lower):
                neighbors[c].add(lower[i])
                neighbors[lower[i]].add(c)
    return neighbors

KEYBOARD_NEIGHBORS = keyboard_neighbors()

def levenstein_distance(s1, s2):

    if len(s1) < len(s2):
        return levenstein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
    return current_row[-1]

def char_diffs (fake_host, real_host):
    if len(fake_host) != len(real_host):
        return []
    return [(f,r) for f,r in zip(fake_host, real_host) if f != r]

# NFKC, punycode + collapse entropy
def normalized_host(value):
    parsed = urlsplit(value)
    # add levenstein?
    host = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
    return unicodedata.normalize ('NFKC', host.lower().strip()).lower()
def is_punycode(host):
    return host.startswith('xn--')

# ASCII-like substitution (non-composite)
def digit_substitution(string, reference=None):
    host = normalized_host(string)
    if not host:
        return False
    if reference:
        real_host = normalized_host(reference)
        diffs = char_diffs(host, real_host)
        for f, r in diffs:
            if f.isdigit() and r.isalpha():
                return True
    return any(f.isdigit() for f in host)
def keyboard_substitution(string, reference=None):
    host = normalized_host(string)
    if not host:
        return False
    if reference:
        real_host = normalized_host(reference)
        diffs = char_diffs(host, real_host)
        for f, r in diffs:
            if f in KEYBOARD_NEIGHBORS and r in KEYBOARD_NEIGHBORS[f]:
                return True
    return any(f in KEYBOARD_NEIGHBORS for f in host)
def multichar_substitution(string, reference=None):
    host = normalized_host(string)
    if not host:
        return False
    if reference:
        real_host = normalized_host(reference)
        diffs = char_diffs(host, real_host)
        for f, r in diffs:
            if len(f) > 1 or len(r) > 1:
                return True
    return any(len(f) > 1 for f in host)

# Multiscript + increase entropy
def mixed_script(string):
    scripts = set(script_bucket(c) for c in string)
    return len(scripts) > 1
# Ligature + decrease entropy
def ligature(string):
    ligatures = ['ﬀ', 'ﬁ', 'ﬂ', 'ﬃ', 'ﬄ', 'ﬅ', 'ﬆ']
    return any(lig in string for lig in ligatures)
# foreign language
def foreign_script(string):
    scripts = set(script_bucket(c) for c in string)
    return any(script not in ['latin', 'ascii'] for script in scripts)

def detect_mechanism(string, target='auto', reference=None):
    if not string:
        return 'empty'
    if target == 'url':
        if is_punycode(normalized_host(string)):
            return 'punycode'
    if reference is not None:
        if digit_substitution(string, reference):
            return 'digit'
        elif keyboard_substitution(string, reference):
            return 'keyboard'
        elif multichar_substitution(string, reference):
            return 'multichar'
    if unicodedata.normalize('NFKC', string) != string:
        return 'nfkc'
    if all(ord(c) < 128 for c in string):
        return 'ascii'

    nonascii_bucket = set()
    has_combining = False
    has_ligature = False
    for char in string:
        bucket = script_bucket(char)
        nonascii_bucket.add(bucket)
        if unicodedata.combining(char):
            has_combining = True
        if char in ['ﬀ', 'ﬁ', 'ﬂ', 'ﬃ', 'ﬄ', 'ﬅ', 'ﬆ']:
            has_ligature = True
        nonascii_bucket.add(script_bucket(char))
        if has_combining:
            return 'combining'
        if has_ligature:
            return 'ligature'
        if len(nonascii_bucket) == 1:
            bucket = next(iter(nonascii_bucket))
            return 'foreign script'
        if unicodedata.normalize('NFKC', string) != string:
            return 'nfkc'
        return 'ascii'

def analyze_url(url, real_url=None):
    # analysis_url = decode_punycode(url) else url
    analysis_url = url
    entropy = shannon_entropy(url, script_aware=False)
    script_entropy = shannon_entropy(url, script_aware=True)
    rarity = transformation_rarity(url)

    nonascii_count = sum(1 for c in url if ord(c) >= 128)
    nonascii_ratio = (nonascii_count/len(analysis_url if analysis_url else 0.0))
    if real_url is not None:
        detected_real = real_url
        similarity = None
    else: 
        detected_real, similarity, _ = nearest_domain(url,real_url)
    mechanism = detect_mechanism(url, target='url', reference=detected_real)
    return {
        'url': url,
        'entropy': entropy,
        'script_entropy': script_entropy,
        'rarity': rarity,
        'nonascii_count': nonascii_count,
        'nonascii_ratio': nonascii_ratio,
        'detected_real': detected_real,
        'similarity': similarity,
        'mechanism': mechanism
    }
if __name__ == "__main__":
    for fake_url, real_url in zip(tests,real):
        for url in (fake_url, real_url):
            h, h_script, rarity, mechanism, detected_real, _, nonascii_count, nonascii_ratio = analyze_url(url, real_url=real_url)
            print(f"{url!r}: entropy={h:.4f}, script_entropy{h_script:.4f}, rarity{rarity:.4f}, mechanism(mechanism), likely={detected_real!r}"))
            
    for unseen_url in (" "):
        h, h_script, rarity, mechanism, detected_real, similarity, nonascii_count, nonascii_ratio = analyze_url(unseen_url)
            print(f"{unseen_url!r}: entropy={h:.4f}, script_entropy{h_script:.4f}, rarity{rarity:.4f}, mechanism(mechanism), detected_real={real_label!r}, similarity={similarity:.4f}"))
