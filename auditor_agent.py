from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from urllib.parse import urlparse
import re


@dataclass
class Evidence:
    tool: str
    score_delta: float
    summary: str
    details: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuditResult:
    decision: str  # ACCEPT or REJECT
    risk_score: float
    confidence: float
    reasoning_chain: List[str]
    evidence: List[Evidence]


class DomainReputationTool:
    trusted_domains = {"python.org", "developer.mozilla.org", "wikipedia.org", "github.com"}
    suspicious_tlds = {"zip", "click", "work", "xyz"}

    def analyze(self, url: str) -> Evidence:
        host = (urlparse(url).hostname or "").lower()
        domain = host[4:] if host.startswith("www.") else host

        if domain in self.trusted_domains:
            return Evidence(
                tool="domain_reputation",
                score_delta=-0.35,
                summary="Domain appears trusted",
                details={"domain": domain, "reputation": "trusted allowlist"},
            )

        tld = domain.split(".")[-1] if "." in domain else ""
        if tld in self.suspicious_tlds:
            return Evidence(
                tool="domain_reputation",
                score_delta=0.35,
                summary="Domain TLD is high-risk",
                details={"domain": domain, "reputation": f"suspicious tld: .{tld}"},
            )

        return Evidence(
            tool="domain_reputation",
            score_delta=0.05,
            summary="Domain reputation is unknown",
            details={"domain": domain, "reputation": "no strong signal"},
        )


class RegexHeuristicTool:
    patterns: Tuple[Tuple[str, float], ...] = (
        (r"ignore\s+previous\s+instructions", 0.35),
        (r"system\s*prompt", 0.2),
        (r"document\.cookie", 0.2),
        (r"fetch\s*\(", 0.1),
        (r"eval\s*\(", 0.25),
        (r"atob\s*\(", 0.15),
        (r"base64", 0.1),
        (r"<iframe[^>]*style=['\"]?display:\s*none", 0.2),
    )

    def analyze(self, content: str) -> Evidence:
        normalized = content.lower()
        hit_patterns: List[str] = []
        score = 0.0
        for pattern, delta in self.patterns:
            if re.search(pattern, normalized):
                score += delta
                hit_patterns.append(pattern)

        if "<script" in normalized and not hit_patterns:
            score += 0.1
            hit_patterns.append("script_tag_present")

        summary = "No high-risk heuristic patterns found" if score <= 0 else "Heuristic risk patterns detected"
        return Evidence(
            tool="regex_heuristic",
            score_delta=score,
            summary=summary,
            details={"patterns": ", ".join(hit_patterns) if hit_patterns else "none"},
        )


class SemanticIntentTool:
    safe_markers = ("analytics", "consent", "documentation", "tutorial", "terms of service")
    risky_markers = (
        "override safety",
        "steal",
        "credential",
        "secret",
        "hidden instruction",
        "jailbreak",
        "bypass",
    )

    def analyze(self, content: str) -> Evidence:
        normalized = content.lower()
        safe_hits = [m for m in self.safe_markers if m in normalized]
        risky_hits = [m for m in self.risky_markers if m in normalized]

        score = 0.0
        if safe_hits:
            score -= min(0.2, 0.05 * len(safe_hits))
        if risky_hits:
            score += min(0.4, 0.1 * len(risky_hits))

        if risky_hits and safe_hits:
            summary = "Mixed semantic intent: both benign and risky cues"
        elif risky_hits:
            summary = "Semantic analysis indicates likely malicious intent"
        elif safe_hits:
            summary = "Semantic analysis indicates benign intent"
        else:
            summary = "Semantic intent is inconclusive"

        return Evidence(
            tool="semantic_intent",
            score_delta=score,
            summary=summary,
            details={
                "safe_hits": ", ".join(safe_hits) if safe_hits else "none",
                "risky_hits": ", ".join(risky_hits) if risky_hits else "none",
            },
        )


class ContentAuditorAgent:
    def __init__(self, reject_threshold: float = 0.65) -> None:
        self.reject_threshold = reject_threshold
        self.domain_tool = DomainReputationTool()
        self.regex_tool = RegexHeuristicTool()
        self.semantic_tool = SemanticIntentTool()

    def _clamp(self, value: float, min_value: float = 0.0, max_value: float = 1.0) -> float:
        return max(min_value, min(max_value, value))

    def audit(self, url: str, content: str) -> AuditResult:
        risk = 0.5
        evidence: List[Evidence] = []
        chain: List[str] = [
            "Start from neutral risk score (0.50).",
            "Select next tool adaptively based on initial content signals.",
        ]

        normalized = content.lower()
        likely_active_code = "<script" in normalized or "eval(" in normalized or "fetch(" in normalized
        host = (urlparse(url).hostname or "").lower()
        domain_trusted = any(host.endswith(d) for d in self.domain_tool.trusted_domains)
        domain_suspicious = bool(host) and not domain_trusted

        if domain_suspicious and likely_active_code:
            chain.append("Unknown domain plus active code detected; run regex heuristics first.")
            first = self.regex_tool.analyze(content)
        else:
            chain.append("Trusted/low-risk source profile; run domain reputation first.")
            first = self.domain_tool.analyze(url)

        risk = self._clamp(risk + first.score_delta)
        evidence.append(first)
        chain.append(f"{first.tool} => {first.summary} (delta {first.score_delta:+.2f}, risk {risk:.2f}).")

        if first.tool != "domain_reputation":
            second = self.domain_tool.analyze(url)
            chain.append("Corroborate heuristic findings with domain reputation.")
        else:
            second = self.regex_tool.analyze(content)
            chain.append("Corroborate domain finding with pattern heuristics.")

        risk = self._clamp(risk + second.score_delta)
        evidence.append(second)
        chain.append(f"{second.tool} => {second.summary} (delta {second.score_delta:+.2f}, risk {risk:.2f}).")

        if 0.35 <= risk <= 0.75:
            chain.append("Risk remains ambiguous after two tools; run semantic intent analysis.")
            third = self.semantic_tool.analyze(content)
            risk = self._clamp(risk + third.score_delta)
            evidence.append(third)
            chain.append(f"{third.tool} => {third.summary} (delta {third.score_delta:+.2f}, risk {risk:.2f}).")
        else:
            chain.append("Risk became decisive after two tools; semantic step skipped.")

        decision = "REJECT" if risk >= self.reject_threshold else "ACCEPT"
        confidence = self._clamp(abs(risk - 0.5) * 1.8 + 0.1 * min(len(evidence), 3), 0.0, 1.0)
        chain.append(
            f"Final decision: {decision} because risk {risk:.2f} is {'above' if decision == 'REJECT' else 'below'} threshold {self.reject_threshold:.2f}."
        )
        chain.append(f"Confidence: {confidence:.2f} based on score distance and corroborating tools.")

        return AuditResult(
            decision=decision,
            risk_score=risk,
            confidence=confidence,
            reasoning_chain=chain,
            evidence=evidence,
        )
