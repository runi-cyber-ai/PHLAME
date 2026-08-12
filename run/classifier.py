#!/usr/bin/env python3
"""Classifier under baseline and each attack, full corpus. Tables 1, 2 and 4.

Asks each model to label every email, once with no attack and once per attack payload
appended to the body.

    python3 run/classifier.py     -> cache/classifier_predictions.jsonl
"""

from __future__ import annotations

import common


def jobs(emails: list[dict]) -> list[dict]:
    out = []
    for model in common.MODELS:
        for attack, payload in common.ATTACKS.items():
            for email in emails:
                body = email["body"] if payload is None else f"{email['body']}\n\n{payload}"
                out.append({
                    "_key": ["model", "attack", "email_id"],
                    "model": model,
                    "attack": attack,
                    "email_id": email["email_id"],
                    "ground_truth": email["ground_truth"],
                    "prompt": common.CLASSIFIER_PROMPT.format(body=body),
                    "allowed": ("phishing", "legitimate"),
                })
    return out


if __name__ == "__main__":
    common.run(jobs(common.load_corpus()), "classifier_predictions.jsonl")
