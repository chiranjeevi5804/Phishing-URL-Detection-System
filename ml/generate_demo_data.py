"""Synthetic demonstration dataset ONLY. Replace with labeled real-world data for serious evaluation."""
import csv
import random
from pathlib import Path

random.seed(42)
brands = ['harbor', 'maple', 'northstar', 'meadow', 'pine', 'orbit', 'atlas', 'silver', 'cloud', 'river']
safe_paths = ['', '/about', '/products', '/blog', '/contact', '/docs', '/support', '/news', '/catalog', '/team']
bad_words = ['verify', 'login', 'account', 'secure', 'password', 'update', 'billing', 'reset', 'unlock', 'confirm']
rows = []
for i in range(1000):
    brand = random.choice(brands)
    domain = f'{brand}{i % 97}.example'
    path = random.choice(safe_paths)
    rows.append((f'https://www.{domain}{path}?ref={i % 9}', 0))
    rows.append((f'http://{random.choice(bad_words)}-{brand}-account{i}.example/{random.choice(bad_words)}/signin?session={i}88&confirm=1', 1))
random.shuffle(rows)
out = Path(__file__).resolve().parents[1] / 'data' / 'urls.csv'
out.parent.mkdir(exist_ok=True)
with out.open('w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['url', 'label'])
    writer.writerows(rows)
print(f'Created {len(rows)} SYNTHETIC example rows at {out}. NOT real-world validation data.')
