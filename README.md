# LLM Safety Evaluation Lab

An exploratory collection of adversarial prompts, manual chat observations, and a prototype API runner. The public evidence is a small pilot record, not a validated safety benchmark or a replicated cross-model study.

## Evidence available

The [attack library](data/attack_library.csv) has **72 unique cases: 43 PENDING and 29 with recorded statuses**. Its actual category counts are:

| Category | Cases |
|---|---:|
| Hallucination | 17 |
| Social Engineering | 14 |
| Prompt Injection | 12 |
| Sensitive Information Disclosure | 9 |
| Excessive Agency | 9 |
| Obfuscated Attack | 4 |
| False Refusal | 3 |
| Ambiguous Intent | 3 |
| Vector and Embedding Weaknesses | 1 |

The non-PENDING rows summarize qualitative observations, sometimes across several consumer interfaces. They lack a complete per-run transcript/metadata trail and are not independent-run counts. Rows 010, 011, and 011a document one ChatGPT chemistry escalation chain; the partial-failure observation does not establish that incremental attacks are generally more effective than direct attacks.

One saved automated batch contains [three ChatGPT response records](output/benchmark_results.json), all labeled PASS by the saved judge output, with a matching [run log](output/benchmark_log.md). This is three prompt evaluations in one batch, not three independent benchmark replications. Judge identity and complete request metadata are not preserved. The CSV still marks case 003 PENDING, so the CSV and automated batch are separate historical records, not a synchronized results database. The [report placeholder](reports/mini_safety_report_v2.md) is empty.

## Runner and reproduction scope

[src/run_benchmark.py](src/run_benchmark.py) implements separate single-prompt API calls for ChatGPT and Claude, optional model-assisted review, keyword checks, and Markdown/JSON/CSV export. It does not implement a conversation-history runner for the manual escalation chains. The presence of this code does not establish that all library cases were executed through it.

Install dependencies from [requirements.txt](requirements.txt). An API-free loading check is:

```bash
python3 src/run_benchmark.py --dry-run
```

This checks library loading only and may create an output directory and `.env.example`. Live execution requires credentials and separate authorization. No new run or judge evaluation is implied here. The repository contains no committed test suite or CI workflow.

## Interpretation and limitations

Manual chat observations, automated response records, keyword scores, and judge interpretations are distinct evidence types. Model aliases, uncontrolled interface settings, missing repeats, inconsistent historical labels, and incomplete transcripts limit reproducibility. Findings do not establish general model rankings, causal bypass mechanisms, or safety guarantees.

[Case studies](case_studies/) and [supplemental notes](notes/) provide external incident/context material; they are not results from this evaluation library. The Fortinet skills-gap note concerns workforce context rather than benchmark evidence. Historical files remain preserved.

[RuSafetyBench](https://github.com/aleksei-khvostov/rusafetybench) contains related Russian-language cases. This repository has not been archived, merged into another project, or formally designated superseded.

Built by [Aleksei Khvostov](https://github.com/aleksei-khvostov). Intended for defensive research and evaluation-method development.
