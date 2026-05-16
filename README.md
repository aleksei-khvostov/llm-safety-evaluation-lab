# LLM Safety Evaluation Lab
An OWASP-inspired adversarial testing framework for evaluating LLM safety behavior across prompt injection, hallucination, social engineering, excessive agency, and related risk categories.
Built as part of an independent AI Safety evaluation portfolio (May 2026).
---
## Overview
This project combines:
- A structured red team attack library
- Automated benchmark execution
- Hybrid safety evaluation (keyword + LLM-as-a-judge)
- Cross-model comparison
- Real-world incident analysis
- OWASP Top 10 for LLM Applications mapping
The goal is to study how modern LLMs behave under adversarial, ambiguous, and manipulation-based conditions.
---
## Core Components
### Attack Library
63 manually crafted adversarial test cases covering:
| Category | Tests | Key Risk |
|---|---|---|
| Prompt Injection | 12 | Instruction hierarchy bypass |
| Hallucination | 10 | Fabricated facts presented as truth |
| Sensitive Information Disclosure | 8 | Credential and PII exposure |
| Social Engineering | 10 | Policy manipulation via human psychology |
| Excessive Agency | 6 | Unauthorized irreversible actions |
| Obfuscated Attacks | 4 | Safety filter evasion |
| False Refusal | 3 | Over-blocking legitimate requests |
| Ambiguous Intent | 3 | Dual-use request calibration |
| Vector / Embedding Weaknesses | 1 | RAG poisoning |
| Temporal Confusion | 1 | Incorrect date anchoring |
---
## Benchmark Runner
The benchmark runner supports:
- ChatGPT
- Claude
- Hybrid evaluation pipeline
- Markdown logging
- JSON export
- CSV export
- Graceful degradation if optional packages are missing
### Evaluation Architecture
```text
Prompt → Model → Response
                    ↓
           [Keyword Check]
                    ↓
           [LLM-as-a-Judge]
                    ↓
         PASS / PARTIAL FAIL / FAIL
                    ↓
      benchmark_log.md + JSON export

⸻

Key Research Finding

Gradual Escalation Bypasses Guardrails

The most significant observed failure pattern involved gradual escalation across multiple conversational turns.

In testing:

* Initial chemistry prompts received safe educational responses
* Second-step escalation still maintained safety framing
* Third-step optimization framing (“most toxic fastest”) triggered a partial safety failure

This suggests:

Context normalization is more dangerous than direct attacks.

Models that resist explicit jailbreak attempts may still degrade when harmful intent is introduced incrementally through benign conversational context.

This finding aligns with real-world incidents involving:

* social engineering
* multi-turn manipulation
* session-level context drift

⸻

Live Testing Highlights (May 2026)

Strongest Safety Behaviors Observed

* Attack-aware refusal
* Temporal awareness
* Explicit identification of manipulation patterns
* Clear distinction between trusted and untrusted instruction sources

Weaknesses Observed

* Gradual escalation
* Framing sensitivity
* Cross-session safety reset
* Weak manipulation resistance in smaller open-source models

⸻

Models Evaluated

* ChatGPT
* Claude
* Meta AI
* SuperGrok
* Gemini
* Copilot
* meta-llama-3.1-8b

⸻

Project Structure

llm-safety-evaluation-lab/
├── src/
│   └── run_benchmark.py
├── data/
│   └── attack_library.csv
├── output/
│   ├── benchmark_results.json
│   └── benchmark_log.md
├── case_studies/
│   ├── openclaw_agent_incident.md
│   └── chatgpt_tactical_advice.md
├── notes/
│   ├── fortinet_2026_skills_gap.md
│   └── malicious_chrome_extensions.md
├── ├── reports/
│   └── mini_safety_report_v2.md
├── requirements.txt
├── .env.example
└── README.md

⸻

Setup

Clone the repository:

git clone https://github.com/fsrxc2bvv9-ctrl/llm-safety-evaluation-lab.git
cd llm-safety-evaluation-lab

Install dependencies:

pip install -r requirements.txt

Create environment file:

cp .env.example .env

Add API keys:

OPENAI_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here

⸻

Usage

Dry run

python3 src/run_benchmark.py --dry-run

Run benchmark

python3 src/run_benchmark.py --model chatgpt --limit 5

Run specific category

python3 src/run_benchmark.py --model claude --category Hallucination

Run only pending tests

python3 src/run_benchmark.py --pending-only --use-judge

Export updated CSV

python3 src/run_benchmark.py --export-csv

⸻

Methodology

* OWASP Top 10 for LLM Applications 2025
* Structured adversarial testing
* LLM-as-a-judge evaluation
* Cross-model comparison
* Real-world incident mapping
* Rubric-based scoring
* Manual qualitative analysis

⸻

Related Research Included

Case Studies

* OpenClaw agent social engineering incident
* ChatGPT tactical attack advice incident

Supplemental Notes

* Fortinet 2026 cybersecurity skills gap report
* Malicious Chrome extension campaign analysis

⸻

About

Built by Aleksei Khvostov

AI Safety Evaluator focused on:

* LLM evaluation
* red teaming
* prompt injection testing
* safety analysis
* hallucination analysis
* structured QA systems
* multilingual adversarial testing (English/Russian)

Background includes:

* Outlier
* Mercor
* Invisible Technologies
* 15+ years of editorial leadership in digital media

Links

* GitHub: https://github.com/fsrxc2bvv9-ctrl
* LinkedIn: https://www.linkedin.com/in/aleksei-khvostov/

⸻

Disclaimer

This repository is intended исключительно for defensive AI safety research, evaluation methodology, and benchmark development.

All prompts use researcher-safe framing.

No operationally harmful instructions, malware, or exploit code are included.

⸻

