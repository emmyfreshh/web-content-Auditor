import json
from pathlib import Path

from auditor_agent import ContentAuditorAgent


ROOT = Path(__file__).resolve().parent
SAMPLES_FILE = ROOT / "demo_samples.json"


def main() -> None:
    samples = json.loads(SAMPLES_FILE.read_text())
    agent = ContentAuditorAgent()

    for sample in samples:
        result = agent.audit(sample["url"], sample["content"])
        print(f"\n=== SAMPLE: {sample['name']} ===")
        print(f"URL: {sample['url']}")
        print(f"Decision: {result.decision}")
        print(f"Risk score: {result.risk_score:.2f}")
        print(f"Confidence: {result.confidence:.2f}")
        print("Reasoning chain:")
        for step in result.reasoning_chain:
            print(f"  - {step}")
        print("Evidence:")
        for ev in result.evidence:
            print(f"  - {ev.tool}: {ev.summary} ({ev.score_delta:+.2f}) | details={ev.details}")


if __name__ == "__main__":
    main()
