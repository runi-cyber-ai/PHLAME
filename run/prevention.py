#!/usr/bin/env python3
"""ICL poisoning against each prompt-prevention scheme. Table 5.

Holds the attack fixed and varies the defense: the strongest injection is wrapped by
each prevention scheme in turn, on the first 300 phishing emails.

    python3 run/prevention.py     -> cache/prevention_predictions.jsonl
"""

from __future__ import annotations

import common


def jobs(emails: list[dict]) -> list[dict]:
    phishing = [e for e in emails if e["ground_truth"] == "phishing"][:common.PREVENTION_SAMPLE]
    payload = common.ATTACKS["ICL_poison"]
    out = []
    for model in common.MODELS:
        for scheme, (prefix, suffix) in common.PREVENTION.items():
            for email in phishing:
                body = f"{prefix}{email['body']}\n\n{payload}{suffix}"
                out.append({
                    "_key": ["model", "surface", "prevention", "condition", "email_id"],
                    "model": model,
                    "surface": "injection",
                    "prevention": scheme,
                    "condition": "ICL_poison",
                    "email_id": email["email_id"],
                    "prompt": common.CLASSIFIER_PROMPT.format(body=body),
                    "allowed": ("phishing", "legitimate"),
                })
    return out


if __name__ == "__main__":
    common.run(jobs(common.load_corpus()), "prevention_predictions.jsonl")
