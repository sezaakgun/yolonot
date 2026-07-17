#!/usr/bin/env python3
"""Generate local JSON test fixtures. Writes only inside ./testdata."""
import json
import os

OUT = os.path.join(os.path.dirname(__file__), "testdata")
os.makedirs(OUT, exist_ok=True)

for i in range(5):
    path = os.path.join(OUT, f"case_{i}.json")
    with open(path, "w") as f:
        json.dump({"id": i, "value": i * 10}, f)

print(f"wrote 5 fixtures to {OUT}")
