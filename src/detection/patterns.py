"""
Split-Up Attack Pattern Detection for OpenSafety AI.

Detects multi-stage attacks that fragment malicious intent across:
- Multiple sequential requests
- Distributed sources (multiple IPs/users)
- Time-delayed campaigns
- Prompt injection fragments
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from detection.tracker import RequestTracker, TrackedRequest


class AttackPatternType(str, Enum):
    """Types of split-up attack patterns."""

    FRAGMENT_ASSEMBLY = (
        "fragment_assembly"  # Pieces of malicious content across requests
    )
    CONTEXT_POISONING = "context_poisoning"  # Gradual context manipulation
    INSTRUCTION_INJECTION = "instruction_injection"  # Hidden instructions in fragments
    ROLE_CONFUSION = "role_confusion"  # Attempts to confuse model roles
    JAILBREAK_SEQUENCE = "jailbreak_sequence"  # Multi-step jailbreak attempts
    DATA_EXFILTRATION = "data_exfiltration"  # Attempts to extract training data
    PROMPT_LEAK = "prompt_leak"  # Attempts to leak system prompts
    COORDINATED_CAMPAIGN = "coordinated_campaign"  # Same attack from multiple sources
    RATE_ABUSE = "rate_abuse"  # High-frequency requests
    SEMANTIC_EVASION = "semantic_evasion"  # Paraphrased malicious intent


@dataclass
class AttackPattern:
    """Detected attack pattern with evidence."""

    pattern_type: AttackPatternType
    confidence: float  # 0.0 to 1.0
    severity: float  # 0.0 to 1.0
    description: str
    evidence: list[str] = field(default_factory=list)
    related_requests: list[str] = field(default_factory=list)  # Request IDs
    metadata: dict[str, Any] = field(default_factory=dict)


class SplitAttackDetector:
    """
    Detects split-up attacks by analyzing patterns across requests.

    Key detection strategies:
    1. Fragment correlation - detecting pieces of harmful content
    2. Behavioral analysis - unusual request patterns
    3. Semantic clustering - related requests with similar intent
    4. Campaign detection - coordinated attacks across sources
    """

    # Suspicious patterns that might indicate split attacks
    INJECTION_MARKERS = [
        r"ignore\s+(previous|above|all)\s+(instructions?|prompts?)",
        r"disregard\s+(your|the)\s+(rules?|guidelines?|instructions?)",
        r"you\s+are\s+now\s+(a|an|in)",
        r"new\s+(instructions?|rules?|mode)",
        r"system:\s*",
        r"<\s*system\s*>",
        r"\[INST\]",
        r"</?(s|system|user|assistant)>",
        r"###\s*(instruction|system|human|assistant)",
        r"^(human|assistant|system):\s*",
    ]

    EXFILTRATION_MARKERS = [
        r"(repeat|output|show|display|print)\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions?)",
        r"what\s+(are|were)\s+your\s+(original|initial|system)\s+(instructions?|prompts?)",
        r"(reveal|expose|leak)\s+(your|the)\s+(training|instructions?|prompts?)",
        r"(pretend|act)\s+like\s+(you\s+)?(don't|do\s+not)\s+have\s+(rules?|restrictions?)",
    ]

    JAILBREAK_MARKERS = [
        r"dan\s*(mode)?",
        r"developer\s+mode",
        r"(enable|activate)\s+(god|admin|root|sudo)\s*(mode)?",
        r"hypothetically",
        r"(for|in)\s+(a\s+)?(fiction|story|novel|movie|game)",
        r"(role\s*play|roleplay|rp)\s+as",
        r"(act|pretend|imagine)\s+(you\s+)?(are|as)\s+(a|an)",
    ]

    CODE_PATTERNS = [
        r"(exec|eval|compile)\s*\(",
        r"import\s+(os|subprocess|sys|socket)",
        r"__import__",
        r"(system|popen|spawn)\s*\(",
        r"\$\([^)]+\)",  # Shell command substitution
        r";\s*(rm|del|format|mkfs)",
    ]

    def __init__(self, tracker: RequestTracker):
        self.tracker = tracker

        # Compile patterns for efficiency
        self._injection_re = [
            re.compile(p, re.IGNORECASE) for p in self.INJECTION_MARKERS
        ]
        self._exfil_re = [
            re.compile(p, re.IGNORECASE) for p in self.EXFILTRATION_MARKERS
        ]
        self._jailbreak_re = [
            re.compile(p, re.IGNORECASE) for p in self.JAILBREAK_MARKERS
        ]
        self._code_re = [re.compile(p, re.IGNORECASE) for p in self.CODE_PATTERNS]

    def analyze_request(
        self,
        request: TrackedRequest,
        message_contents: list[str],
        system_prompt: Optional[str] = None,
    ) -> list[AttackPattern]:
        """
        Analyze a single request for attack patterns.
        Returns list of detected patterns.
        """
        patterns = []
        full_content = " ".join(message_contents)

        # 1. Check for direct injection markers
        patterns.extend(self._detect_injection_patterns(full_content, request))

        # 2. Check for exfiltration attempts
        patterns.extend(self._detect_exfiltration_patterns(full_content, request))

        # 3. Check for jailbreak sequences
        patterns.extend(self._detect_jailbreak_patterns(full_content, request))

        # 4. Check for dangerous code
        patterns.extend(self._detect_code_patterns(full_content, request))

        # 5. Analyze request in context of recent history
        patterns.extend(self._detect_temporal_patterns(request))

        # 6. Check for coordinated campaigns
        patterns.extend(self._detect_campaign_patterns(request))

        # 7. Check for fragment assembly
        patterns.extend(self._detect_fragment_patterns(request, message_contents))

        return patterns

    def _detect_injection_patterns(
        self, content: str, request: TrackedRequest
    ) -> list[AttackPattern]:
        """Detect prompt injection markers."""
        patterns = []
        matches = []

        for regex in self._injection_re:
            found = regex.findall(content)
            if found:
                matches.extend(
                    found if isinstance(found[0], str) else [f[0] for f in found]
                )

        if matches:
            confidence = min(0.3 + 0.15 * len(matches), 0.95)
            patterns.append(
                AttackPattern(
                    pattern_type=AttackPatternType.INSTRUCTION_INJECTION,
                    confidence=confidence,
                    severity=0.7,
                    description=f"Detected {len(matches)} potential injection markers",
                    evidence=matches[:5],  # Limit evidence size
                    related_requests=[request.request_id],
                )
            )

        return patterns

    def _detect_exfiltration_patterns(
        self, content: str, request: TrackedRequest
    ) -> list[AttackPattern]:
        """Detect prompt/data exfiltration attempts."""
        patterns = []
        matches = []

        for regex in self._exfil_re:
            found = regex.findall(content)
            if found:
                matches.extend(
                    found if isinstance(found[0], str) else [str(f) for f in found]
                )

        if matches:
            patterns.append(
                AttackPattern(
                    pattern_type=AttackPatternType.PROMPT_LEAK,
                    confidence=min(0.5 + 0.1 * len(matches), 0.9),
                    severity=0.8,
                    description="Detected attempt to extract system prompt or training data",  # noqa: E501
                    evidence=matches[:3],
                    related_requests=[request.request_id],
                )
            )

        return patterns

    def _detect_jailbreak_patterns(
        self, content: str, request: TrackedRequest
    ) -> list[AttackPattern]:
        """Detect jailbreak sequence markers."""
        patterns = []
        matches = []

        for regex in self._jailbreak_re:
            found = regex.findall(content)
            if found:
                matches.extend(
                    found if isinstance(found[0], str) else [str(f) for f in found]
                )

        if matches:
            patterns.append(
                AttackPattern(
                    pattern_type=AttackPatternType.JAILBREAK_SEQUENCE,
                    confidence=min(0.4 + 0.12 * len(matches), 0.85),
                    severity=0.6,
                    description=f"Detected {len(matches)} jailbreak indicators",
                    evidence=matches[:3],
                    related_requests=[request.request_id],
                )
            )

        return patterns

    def _detect_code_patterns(
        self, content: str, request: TrackedRequest
    ) -> list[AttackPattern]:
        """Detect potentially dangerous code patterns."""
        patterns = []
        matches = []

        for regex in self._code_re:
            found = regex.findall(content)
            if found:
                matches.extend(
                    found if isinstance(found[0], str) else [str(f) for f in found]
                )

        if matches:
            patterns.append(
                AttackPattern(
                    pattern_type=AttackPatternType.DATA_EXFILTRATION,
                    confidence=min(0.35 + 0.15 * len(matches), 0.8),
                    severity=0.75,
                    description="Detected potentially dangerous code execution patterns",  # noqa: E501
                    evidence=matches[:3],
                    related_requests=[request.request_id],
                    metadata={"code_patterns": matches},
                )
            )

        return patterns

    def _detect_temporal_patterns(self, request: TrackedRequest) -> list[AttackPattern]:
        """Analyze request rate and timing patterns."""
        patterns = []

        # Check IP request rate
        ip_rate = self.tracker.get_ip_request_rate(request.client_ip, window_seconds=60)
        if ip_rate > 10:  # More than 10 requests per minute
            patterns.append(
                AttackPattern(
                    pattern_type=AttackPatternType.RATE_ABUSE,
                    confidence=min(0.3 + (ip_rate - 10) * 0.05, 0.9),
                    severity=0.5,
                    description=f"High request rate from IP: {ip_rate:.1f}/min",
                    evidence=[f"Rate: {ip_rate:.1f} requests/minute"],
                    related_requests=[request.request_id],
                    metadata={"rate_per_minute": ip_rate},
                )
            )

        # Check for burst patterns (many requests in short window)
        recent_from_ip = self.tracker.get_requests_by_ip(
            request.client_ip, window_seconds=10
        )
        if len(recent_from_ip) > 5:
            patterns.append(
                AttackPattern(
                    pattern_type=AttackPatternType.RATE_ABUSE,
                    confidence=0.6,
                    severity=0.6,
                    description=f"Burst detected: {len(recent_from_ip)} requests in 10 seconds",  # noqa: E501
                    evidence=[f"Requests in burst: {len(recent_from_ip)}"],
                    related_requests=[r.request_id for r in recent_from_ip[-5:]],
                )
            )

        return patterns

    def _detect_campaign_patterns(self, request: TrackedRequest) -> list[AttackPattern]:
        """Detect coordinated campaigns using same content from multiple sources."""
        patterns = []

        if request.content_hash:
            unique_ips = self.tracker.count_unique_ips_for_content(
                request.content_hash,
                window_seconds=3600,  # 1 hour window
            )

            if unique_ips >= 3:  # Same content from 3+ IPs
                related = self.tracker.get_requests_by_content(request.content_hash)
                patterns.append(
                    AttackPattern(
                        pattern_type=AttackPatternType.COORDINATED_CAMPAIGN,
                        confidence=min(0.4 + unique_ips * 0.1, 0.9),
                        severity=0.8,
                        description=f"Same content from {unique_ips} different IPs",
                        evidence=[f"Unique source IPs: {unique_ips}"],
                        related_requests=[r.request_id for r in related[-10:]],
                        metadata={
                            "unique_ips": unique_ips,
                            "content_hash": request.content_hash,
                        },
                    )
                )

        # Check for same system prompt from many sources (campaign detection)
        if request.system_prompt_hash:
            system_requests = self.tracker.get_requests_by_system_prompt(
                request.system_prompt_hash, window_seconds=3600
            )
            unique_ips = len(set(r.client_ip for r in system_requests))

            if unique_ips >= 5 and len(system_requests) >= 10:
                patterns.append(
                    AttackPattern(
                        pattern_type=AttackPatternType.COORDINATED_CAMPAIGN,
                        confidence=min(0.5 + unique_ips * 0.05, 0.85),
                        severity=0.7,
                        description=f"Identical system prompt from {unique_ips} IPs ({len(system_requests)} requests)",  # noqa: E501
                        evidence=[
                            f"System prompt hash: {request.system_prompt_hash[:8]}..."
                        ],
                        related_requests=[r.request_id for r in system_requests[-10:]],
                    )
                )

        return patterns

    def _detect_fragment_patterns(
        self, request: TrackedRequest, message_contents: list[str]
    ) -> list[AttackPattern]:
        """
        Detect split-up attacks where fragments assemble into malicious content.
        Looks for patterns across recent requests from same source.
        """
        patterns = []

        # Get recent requests from same IP
        recent = self.tracker.get_requests_by_ip(request.client_ip, window_seconds=300)
        if len(recent) < 3:
            return patterns

        # Check for increasing diversity of content (fragmentation signal)
        unique_contents = self.tracker.count_unique_content_from_ip(
            request.client_ip, 300
        )
        if unique_contents > 10:
            patterns.append(
                AttackPattern(
                    pattern_type=AttackPatternType.FRAGMENT_ASSEMBLY,
                    confidence=min(0.3 + unique_contents * 0.03, 0.7),
                    severity=0.65,
                    description=f"High content diversity: {unique_contents} unique messages in 5 minutes",  # noqa: E501
                    evidence=[f"Unique content hashes: {unique_contents}"],
                    related_requests=[r.request_id for r in recent[-5:]],
                )
            )

        # Check for sequential numbering or continuation patterns in messages
        continuation_signals = 0
        for content in message_contents:
            lower = content.lower()
            if any(
                marker in lower
                for marker in [
                    "continued",
                    "part 2",
                    "part 3",
                    "continuation",
                    "as mentioned",
                    "following up",
                    "next step",
                    "building on",
                    "to continue",
                ]
            ):
                continuation_signals += 1

        if continuation_signals > 0 and len(recent) > 2:
            patterns.append(
                AttackPattern(
                    pattern_type=AttackPatternType.FRAGMENT_ASSEMBLY,
                    confidence=0.5,
                    severity=0.5,
                    description="Detected continuation/sequencing language suggesting multi-part content",  # noqa: E501
                    evidence=[f"Continuation signals: {continuation_signals}"],
                    related_requests=[r.request_id for r in recent[-3:]],
                )
            )

        return patterns

    def get_combined_threat_score(self, patterns: list[AttackPattern]) -> float:
        """Calculate combined threat score from all detected patterns."""
        if not patterns:
            return 0.0

        # Weighted combination considering both confidence and severity
        scores = [(p.confidence * p.severity) for p in patterns]

        # Use diminishing returns for multiple patterns
        # First pattern counts full, subsequent patterns add less
        scores.sort(reverse=True)
        combined = 0.0
        weight = 1.0
        for score in scores:
            combined += score * weight
            weight *= 0.6  # Diminishing weight

        # Normalize to 0-1 range
        return min(combined, 1.0)
