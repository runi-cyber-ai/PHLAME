# PHLAME — Phishing LLM Adversarial Mitigation Ensemble

Artifact for *Inference Attacks and Defenses on LLM-Powered Phishing Email Detection
Systems*, HumSec 2026 (ESORICS workshops).

PHLAME is an LLM-only phishing detector. It splits detection into three yes/no
questions and answers each with a different model, flagging an email if any component
fires. Across all 216 possible role assignments the balanced route catches at least
99.5% of phishing on every tested attack surface at 2.0% false alarms.

The finding behind it is *detection–robustness decoupling*: how well a model classifies
email says nothing about how well it resists an attack aimed at itself, so the two jobs
should not go to the same model. Claude Opus 4.8 is the strongest clean classifier at
98.9% recall, yet spots only 59% of in-context injections. Gemini 3.1 Pro spots about
100% of them. Neither is simply better. They are good at different things, which is why
PHLAME gives each model the role it measured best at rather than picking one winner:

| Role | Question | Balanced route |
|---|---|---|
| Classifier | Is this email phishing? | Claude Sonnet 4.6 |
| Injection guard | Is something in this email trying to manipulate the classifier? | Gemini 3.1 Pro |
| Intent guard | Does this email ask for a risky action? | Claude Opus 4.8 |

Opus appears as the intent guard, not the classifier, because it pairs a low false-alarm
rate with the ability to spot a risky request in a rewritten email. The same model is an
asset in one seat and a liability in another.

## Attacks and defenses

Nine inference-time attacks, in two families by what the attacker manipulates:

| Attack | Family | What it does |
|---|---|---|
| `I0` naive | LLM manipulation | Tells the model to ignore instructions and answer legitimate |
| `I1` safety refusal | LLM manipulation | Disallowed-content request that makes aligned models refuse |
| `I2` denial of service | LLM manipulation | Long-output request that stalls the call |
| `I1_refusal_redirect` | LLM manipulation | Frames "legitimate" as the safe answer |
| `ICL_poison` | LLM manipulation | Fake reference labels teaching the model to answer legitimate |
| `CoT_fewshot` | LLM manipulation | Poisoned labels plus a fabricated reasoning trace |
| `Auth_cot_combo` | LLM manipulation | Spoofed SPF/DKIM/DMARC headers plus a fake analyst pre-scan |
| `guard_aware_inj` | LLM manipulation | Fixed payload posing as ordinary footer text to slip past a guard |
| Content rewriting | Content manipulation | Rewrites the email to drop familiar cues but keep the request |

Defenses, in two layers:

| Defense | Type | Idea |
|---|---|---|
| `sandwich` | Prompt prevention | Repeats the task after the untrusted email |
| `delimiters` | Prompt prevention | Fences the email as data |
| `delimiters_and_content_guard` | Prompt prevention | Fences it and says to ignore instructions inside |
| `instructional` | Prompt prevention | Warns the model the email may try to instruct it |
| `known_answer` | Prompt prevention | Checks a control word to detect hijacking |
| Injection guard | Separate call | Asks whether the email contains injected instructions |
| Rewrite guard | Separate call | Asks whether the email looks machine-rewritten |
| Intent guard | Separate call | Asks whether the email requests a risky action |

Prompt prevention helps but never closes the gap; the separate guard calls are what make
routing work, because a guard fails independently of the classifier.

## Layout

```
explore.ipynb   rebuilds the paper's tables from results/ and plots the findings
prompts/        one file per prompt: classifier, attacks, prevention, each guard
data/           the fixed 200 + 200 evaluation cohort, ids only
run/            classifier.py, guard.py, prevention.py, the two discriminative baselines
results/        what the experiments produced
```

`explore.ipynb` is the quickest way in. It needs only `pandas` and `matplotlib`, reads
`results/` directly, and reproduces Tables 1, 2, 4, 5, 7 and 10 along with the
decoupling scatter and the 216-assignment trade-off plot. It is stored with its outputs,
so it can be read on GitHub without running anything.

`results/` is all CSV. Three files hold 256,626 individual model verdicts, keyed by
email id: `classifier_predictions.csv` (baseline and eight attacks),
`guard_predictions.csv`, and `prevention_predictions.csv`. Tables 1, 2, 4, 5, 6 and 7
are computed from those three alone.

The rest are results that cannot be derived from them: `role_assignments.csv` (all 216
role combinations, Table 10), `operational_latency.csv` (measured wall-clock),
`routing_holdout.csv` and `routing_leave_one_attack_out.csv` (route-selection checks),
`call_volume*.csv` (cost), the two discriminative baselines, and the second corpus.

Email bodies are not included. Nazario-5 comes from
<https://doi.org/10.5281/zenodo.8339691>, and the predictions are keyed by its ids. The
raw API responses and the 381 verified rewrites are a separate release, since the
rewrites contain generated phishing text.

This repository contains working prompt-injection payloads, published so defenders can
test their own detectors. Do not use them against systems you do not own or have
permission to test.

## Models

Mid-tier: Claude Sonnet 4.6, Gemini 3.5 Flash, GPT-5.4 mini.
Frontier: Claude Opus 4.8, GPT-5.5, Gemini 3.1 Pro.
