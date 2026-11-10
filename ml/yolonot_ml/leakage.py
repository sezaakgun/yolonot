"""Keep the shipped eval suites out of the training data.

The greenfield / script-attach / brownfield suites are the only honest
yardstick against Jev and the chat models, so a training command that is the
same as, or a near copy of, an eval command is dropped.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, List, Set, Tuple

SUITES_DIR = Path(__file__).resolve().parents[2] / "evals" / "suites"

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*|[^\sA-Za-z0-9]")


def normalize(cmd: str) -> str:
    cmd = cmd.strip().lower()
    cmd = re.sub(r"\d+", "0", cmd)
    return re.sub(r"\s+", " ", cmd)


def tokens(cmd: str) -> Set[str]:
    return set(_TOKEN.findall(normalize(cmd)))


def eval_commands(suites_dir: Path = SUITES_DIR) -> List[str]:
    out: List[str] = []
    for path in sorted(suites_dir.glob("*.jsonl")):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                case = json.loads(line)
                out.append(case["command"])
                out.extend(case.get("approved") or [])
    return out


class LeakageFilter:
    def __init__(self, reference: Iterable[str], jaccard: float = 0.8):
        self.ref: List[Tuple[str, Set[str]]] = [(normalize(c), tokens(c)) for c in reference]
        self.exact = {n for n, _ in self.ref}
        self.jaccard = jaccard

    def leaks(self, cmd: str) -> bool:
        n = normalize(cmd)
        if n in self.exact:
            return True
        t = tokens(cmd)
        if not t:
            return False
        for _, rt in self.ref:
            inter = len(t & rt)
            if inter and inter / len(t | rt) >= self.jaccard:
                return True
        return False
