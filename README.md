# web-content-Auditor

A lightweight multi-step agent that audits untrusted web content and decides whether to **ACCEPT** it for ingestion or **REJECT** it.

## What this agent does

`ContentAuditorAgent` ingests a URL + content body (HTML/text/API response) and:
1. Gathers evidence from multiple tools.
2. Adapts the next check based on intermediate findings (not fixed order).
3. Produces a binary decision (`ACCEPT`/`REJECT`).
4. Logs a full reasoning chain and tool evidence for auditability.

## Detection strategy and trade-offs

The agent combines three tools:
- **Domain reputation tool** (source trust signal)
- **Regex heuristic tool** (prompt-injection + risky JavaScript pattern signal)
- **Semantic intent tool** (contextual benign-vs-malicious signal)

### Why this weighting?
- We start at neutral risk `0.50`.
- Strong trust signal lowers risk (`-0.35`), high-risk TLD raises risk (`+0.35`).
- Heuristic matches raise risk by pattern severity.
- Semantic signals are weighted less aggressively (max ±0.4) to avoid overreacting to keywords without context.

This balances **precision** (clear malware gets rejected) and **recall** (ambiguous-but-benign content can still be accepted if context is supportive).

### Decision threshold
- **Reject threshold: `0.65`**
- `risk >= 0.65` => `REJECT`
- `risk < 0.65` => `ACCEPT`

Rationale: with neutral start at `0.50`, a rejection requires multiple corroborating risk signals or one very strong signal + supporting evidence.

## Adaptive workflow (non-fixed sequence)

The agent decides check order at runtime:
- If active code or unknown/suspicious source is detected first, run **regex heuristics** first.
- Otherwise, run **domain reputation** first.
- Always run a second corroborating tool.
- If still ambiguous (`0.35 <= risk <= 0.75`), run **semantic intent** as tie-break evidence.

## Demo

Three sample inputs are included in `demo_samples.json`:
- `benign` (clearly safe)
- `malicious` (clearly malicious)
- `ambiguous` (mixed signals)

Run:

```bash
python run_demo.py
```

The script prints each sample’s decision, risk score, confidence, full reasoning chain, and all tool evidence.

## Tests

Run focused tests:

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

Coverage validates:
- benign gets accepted
- malicious gets rejected
- multiple distinct tools are used
- tool order adapts by input
