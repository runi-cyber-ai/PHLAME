#!/usr/bin/env python3
"""Injection guard over every condition, full corpus. Tables 6 and 7.

Asks each model whether an email contains instructions aimed at an automated
classifier. Injected phishing should come back `injection`; unmodified email is the
clean control and should come back `clean`.

    python3 run/guard.py     -> cache/guard_predictions.jsonl
"""

from __future__ import annotations

import common


def jobs(emails: list[dict]) -> list[dict]:
    phishing = [e for e in emails if e["ground_truth"] == "phishing"]
    out = []
    for model in common.MODELS:
        for attack, payload in common.ATTACKS.items():
            if payload is None:  # baseline has no payload to detect
                continue
            for email in phishing:
                out.append({
                    "_key": ["model", "condition", "email_id"],
                    "model": model,
                    "condition": attack,
                    "email_id": email["email_id"],
                    "true_label": "injection",
                    "prompt": common.GUARD_PROMPT.format(body=f"{email['body']}\n\n{payload}"),
                    "allowed": ("injection", "clean"),
                })
        for email in emails:
            clean = "clean_phishing" if email["ground_truth"] == "phishing" else "clean_legitimate"
            out.append({
                "_key": ["model", "condition", "email_id"],
                "model": model,
                "condition": clean,
                "email_id": email["email_id"],
                "true_label": "clean",
                "prompt": common.GUARD_PROMPT.format(body=email["body"]),
                "allowed": ("injection", "clean"),
            })
    return out


if __name__ == "__main__":
    common.run(jobs(common.load_corpus()), "guard_predictions.jsonl")
