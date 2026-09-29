"""Run the synthetic injection corpus against isolated gateway sessions.

No external model is involved: each untrusted instruction has a recorded tool
request so a policy change can be measured deterministically.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent_firewall import ActionRequest, Gateway  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class DenyApproval:
    def approve(self, _decision):
        return False


def run_corpus() -> list[str]:
    data = json.loads((ROOT / "corpus/attacks.json").read_text(encoding="utf-8"))
    if data["version"] != 1:
        raise ValueError("unsupported corpus version")
    failures: list[str] = []
    for case in data["cases"]:
        with tempfile.TemporaryDirectory(prefix="vt-firewall-corpus-") as directory:
            temp = Path(directory)
            shutil.copytree(ROOT / "demo_workspace", temp / "demo_workspace", symlinks=True)
            gateway = Gateway(ROOT / "policies/default.json", temp / "audit.jsonl",
                              approver=DenyApproval(), base_dir=temp)
            try:
                for number, step in enumerate(case["steps"], 1):
                    result = gateway.handle(ActionRequest(actor="corpus", tool=step["tool"],
                                                          params=step["params"]))
                    if (result["decision"], result["rule_id"]) != (step["decision"], step["rule_id"]):
                        failures.append(f"{case['id']} step {number}: got {result['decision']}/{result['rule_id']}")
                    if result["decision"] == "block" and result["outcome"] != "not_executed":
                        failures.append(f"{case['id']} step {number}: blocked action executed")
            finally:
                if gateway.audit is not None:
                    gateway.audit.close()
            records = (temp / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            expected = sum(2 if step["decision"] == "allow" else 1 for step in case["steps"])
            if len(records) != expected:
                failures.append(f"{case['id']}: audit has {len(records)} records, expected {expected}")
            parsed = [json.loads(record) for record in records]
            for index, record in enumerate(parsed):
                if record["outcome"] == "intent":
                    if index + 1 >= len(parsed) or parsed[index + 1].get("action_id") != record.get("action_id"):
                        failures.append(f"{case['id']}: unresolved audit intent")
            if (temp / "demo_workspace/canary/must-remain.txt").read_text() != "untouched\n":
                failures.append(f"{case['id']}: canary changed")
    return failures


if __name__ == "__main__":
    problems = run_corpus()
    print(f"corpus: {len(json.loads((ROOT / 'corpus/attacks.json').read_text())['cases'])} cases, {len(problems)} failures")
    for problem in problems:
        print(problem)
    raise SystemExit(bool(problems))
