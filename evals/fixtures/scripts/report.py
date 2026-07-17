#!/usr/bin/env python3
"""Read a local CSV and print a summary. Read-only, no network."""
import csv
import os
import sys

path = os.path.join(os.path.dirname(__file__), "testdata", "metrics.csv")
if not os.path.exists(path):
    print("no data")
    sys.exit(0)

total = 0
with open(path) as f:
    for row in csv.DictReader(f):
        total += int(row.get("count", 0))
print(f"total: {total}")
