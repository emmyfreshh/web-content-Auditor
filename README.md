# web-content-Auditor

A multi-step agent that audits untrusted web content and makes a binary `accept`/`reject` ingestion decision with an auditable reasoning chain.

## What this implements

- Multi-step decision agent for untrusted inputs (HTML/text/API-like payloads)
- Evidence gathering from **multiple distinct tools**
- Adaptive check ordering (the agent changes what it checks next based on findings)
- Full reasoning trace for each decision
- Three demo samples:
  - clearly benign
  - clearly malicious
  - ambiguous

## Detection strategy

The agent combines four evidence tools and uses weighted risk scoring:

1. **Local semantic intent analyzer**
   - Interprets whether script/text intent appears benign, malicious, or uncertain.
2. **Pattern heuristic checker**
   - Detects prompt-injection phrases, XSS signatures, obfuscation, and exfil markers.
3. **Domain reputation service (simulated external check)**
   - Scores trusted/unknown/suspicious domains.
4. **Script sandbox simulator**
   - Infers risky runtime behavior signals (dynamic execution, credential access, exfiltration).

### Why this weighting

- Semantic analysis gets the highest weight (0.35) to reduce false positives where raw regex alone is noisy.
- Pattern matching (0.30) is strong for known exploit signatures.
- Reputation (0.20) informs trust context but does not dominate content evidence.
- Sandbox simulation (0.15) provides behavior corroboration when scripts are present.

The default reject threshold is **0.60** weighted risk.

## Adaptive behavior (not fixed sequence)

The agent does not run the same checks in the same order every time:

- If script-like content is detected, it starts with semantic intent.
- If no script but a source URL exists, it starts with reputation.
- If uncertainty remains, it chooses the next tool that most reduces uncertainty (often sandbox or pattern checks).
- It stops when evidence is decisive and at least two tools have been used.

## How to run this application
```bash
streamlit run streamlit_app.py
```

## Future Improvements
Future improvements that will be considered for this system includes; an ML model or NLP model instead of the semantic analyzer, a database of known bad domains and more risk categories.


## Run the demo in the tests folder

From repository root:

```bash
python auditor_agent.py
```

This prints JSON decisions for three examples, each including:

- tool-by-tool steps
- why each tool was selected next
- per-tool evidence and risk
- final accept/reject rationale

## Run tests

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```

## demo script 

1. Run `python auditor_agent.py`.
2. Show `benign-doc-page` being accepted with low weighted risk.
3. Show `malicious-injection` being rejected with high-risk corroborated evidence.
4. Show `ambiguous-analytics-snippet` and explain uncertainty handling + additional checks.
5. Highlight the logged reasoning chain and why the final decision is defensible.
