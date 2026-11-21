import ipaddress
import math
import re
from urllib.parse import urlsplit

SUSPICIOUS = ('login', 'verify', 'secure', 'update', 'account', 'password', 'confirm', 'wallet', 'billing', 'signin', 'unlock', 'urgent', 'reset')
SHORTENERS = ('bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy')

def normalize_url(value):
    value = str(value).strip()
    if not value or len(value) > 2048 or any(c.isspace() for c in value):
        raise ValueError('Enter a valid URL (maximum 2048 characters, no spaces).')
    if not re.match(r'^https?://', value, flags=re.I):
        value = 'https://' + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
        raise ValueError('Enter a valid HTTP or HTTPS URL.')
    if parts.username or parts.password:
        raise ValueError('URLs containing credentials are not supported.')
    try:
        _ = parts.port
    except ValueError:
        raise ValueError('Invalid URL port.')
    if len(parts.hostname) > 253 or not re.fullmatch(r'[a-zA-Z0-9.:-]+', parts.hostname):
        raise ValueError('Invalid hostname.')
    return value

def extract_features(value):
    url = normalize_url(value)
    parts = urlsplit(url)
    host = (parts.hostname or '').lower()
    path = parts.path.lower()
    lower = url.lower()
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0
    tokens = re.findall(r'[a-z]+', lower)
    counts = [lower.count(ch) for ch in '.-@?=&%_/']
    return {
        'url_length': len(url), 'hostname_length': len(host),
        'path_length': len(parts.path), 'query_length': len(parts.query),
        'digit_count': sum(ch.isdigit() for ch in url),
        'dot_count': lower.count('.'), 'hyphen_count': lower.count('-'),
        'at_count': lower.count('@'), 'question_count': lower.count('?'),
        'equals_count': lower.count('='), 'ampersand_count': lower.count('&'),
        'percent_count': lower.count('%'), 'slash_count': lower.count('/'),
        'underscore_count': lower.count('_'),
        'special_count': sum(counts),
        'subdomain_count': max(0, len(host.split('.')) - 2),
        'uses_https': int(parts.scheme.lower() == 'https'),
        'has_ip_address': is_ip,
        'suspicious_keyword_count': sum(token in SUSPICIOUS for token in tokens),
        'is_shortener': int(host in SHORTENERS),
        'has_port': int(parts.port is not None),
        'has_punycode': int('xn--' in host),
        'has_double_slash_path': int('//' in parts.path),
        'has_fragment': int(bool(parts.fragment)),
        'entropy': round(-sum((lower.count(c)/len(lower))*math.log2(lower.count(c)/len(lower)) for c in set(lower)), 5)
    }
