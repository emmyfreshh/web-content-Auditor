import json
from pathlib import Path
import unittest

from auditor_agent import ContentAuditorAgent


class ContentAuditorAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.samples = json.loads((root / "demo_samples.json").read_text())
        cls.agent = ContentAuditorAgent()

    def test_benign_content_is_accepted(self):
        sample = next(s for s in self.samples if s["name"] == "benign")
        result = self.agent.audit(sample["url"], sample["content"])
        self.assertEqual(result.decision, "ACCEPT")

    def test_malicious_content_is_rejected(self):
        sample = next(s for s in self.samples if s["name"] == "malicious")
        result = self.agent.audit(sample["url"], sample["content"])
        self.assertEqual(result.decision, "REJECT")

    def test_reasoning_chain_and_multi_tool_evidence_exist(self):
        sample = next(s for s in self.samples if s["name"] == "ambiguous")
        result = self.agent.audit(sample["url"], sample["content"])
        self.assertGreaterEqual(len(result.evidence), 2)
        tools_used = {e.tool for e in result.evidence}
        self.assertGreaterEqual(len(tools_used), 2)
        self.assertTrue(any("Final decision" in step for step in result.reasoning_chain))

    def test_agent_uses_adaptive_tool_order(self):
        benign = next(s for s in self.samples if s["name"] == "benign")
        malicious = next(s for s in self.samples if s["name"] == "malicious")
        benign_result = self.agent.audit(benign["url"], benign["content"])
        malicious_result = self.agent.audit(malicious["url"], malicious["content"])
        self.assertNotEqual(benign_result.evidence[0].tool, malicious_result.evidence[0].tool)


if __name__ == "__main__":
    unittest.main()
