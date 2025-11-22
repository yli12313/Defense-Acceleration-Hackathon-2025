"""
Threat Analyzer for OpenSafety AI.
Aggregates signals and provides final threat assessment.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from detection.fingerprint import (
    AdvancedFingerprinter,
    ContentFingerprint,
)
from detection.patterns import AttackPattern, AttackPatternType, SplitAttackDetector
from detection.tracker import RequestTracker, TrackedRequest, hash_api_key, hash_content


class ThreatLevel(str, Enum):
    """Threat severity levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatAction(str, Enum):
    """Recommended actions for threats."""

    ALLOW = "allow"
    LOG = "log"  # Allow but log for review
    RATE_LIMIT = "rate_limit"  # Slow down requests
    CHALLENGE = "challenge"  # Require additional verification
    BLOCK = "block"  # Block the request
    QUARANTINE = "quarantine"  # Block and flag for investigation


@dataclass
class ThreatSignal:
    """Individual threat signal from analysis."""

    name: str
    score: float  # 0.0 to 1.0
    description: str
    category: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatAssessment:
    """Complete threat assessment for a request."""

    request_id: str
    threat_score: float  # 0.0 to 1.0
    threat_level: ThreatLevel
    recommended_action: ThreatAction

    # Detailed signals
    signals: list[ThreatSignal] = field(default_factory=list)
    patterns: list[AttackPattern] = field(default_factory=list)

    # Context
    is_repeat_offender: bool = False
    related_threat_count: int = 0

    # Explanation
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class ThreatAnalyzer:
    """
    Main threat analysis engine for OpenSafety AI.

    Combines multiple detection strategies:
    - Pattern matching (injection, jailbreak, etc.)
    - Behavioral analysis (rate, timing)
    - Historical correlation (repeat offenders)
    - Campaign detection (coordinated attacks)
    """

    # Thresholds for threat levels
    THRESHOLDS = {
        ThreatLevel.LOW: 0.2,
        ThreatLevel.MEDIUM: 0.4,
        ThreatLevel.HIGH: 0.6,
        ThreatLevel.CRITICAL: 0.8,
    }

    # Action mappings
    ACTION_MAP = {
        ThreatLevel.NONE: ThreatAction.ALLOW,
        ThreatLevel.LOW: ThreatAction.LOG,
        ThreatLevel.MEDIUM: ThreatAction.RATE_LIMIT,
        ThreatLevel.HIGH: ThreatAction.CHALLENGE,
        ThreatLevel.CRITICAL: ThreatAction.BLOCK,
    }

    def __init__(
        self,
        tracker: Optional[RequestTracker] = None,
        blocking_enabled: bool = False,  # Default to monitoring mode
        blocking_threshold: float = 0.8,
        enable_fingerprinting: bool = True,
    ):
        self.tracker = tracker or RequestTracker()
        self.detector = SplitAttackDetector(self.tracker)
        self.blocking_enabled = blocking_enabled
        self.blocking_threshold = blocking_threshold
        self.enable_fingerprinting = enable_fingerprinting

        # Advanced fingerprinting for similarity detection
        self.fingerprinter = AdvancedFingerprinter() if enable_fingerprinting else None

        # Track repeat offenders (IPs with multiple high-threat requests)
        self._offender_scores: dict[str, float] = {}

        # Cache recent fingerprints for correlation
        self._recent_fingerprints: dict[str, ContentFingerprint] = {}

    def analyze(
        self,
        request: TrackedRequest,
        messages: list[dict[str, Any]],
        api_key: Optional[str] = None,
    ) -> ThreatAssessment:
        """
        Perform complete threat analysis on a request.

        Args:
            request: The tracked request metadata
            messages: The chat messages from the request
            api_key: Optional API key for additional correlation

        Returns:
            ThreatAssessment with score, level, and recommended action
        """
        signals = []
        all_patterns = []

        # Extract message contents for analysis
        message_contents = self._extract_contents(messages)
        system_prompt = self._extract_system_prompt(messages)

        # Update request with computed hashes
        if message_contents:
            request.content_hash = hash_content(" ".join(message_contents))
        if system_prompt:
            request.system_prompt_hash = hash_content(system_prompt)
        if api_key:
            request.api_key_hash = hash_api_key(api_key)

        # 1. Pattern-based detection
        patterns = self.detector.analyze_request(
            request, message_contents, system_prompt
        )
        all_patterns.extend(patterns)

        for pattern in patterns:
            signals.append(
                ThreatSignal(
                    name=pattern.pattern_type.value,
                    score=pattern.confidence * pattern.severity,
                    description=pattern.description,
                    category="pattern",
                    metadata={"evidence": pattern.evidence[:3]},
                )
            )

        # 2. Behavioral analysis
        behavioral_signals = self._analyze_behavior(request)
        signals.extend(behavioral_signals)

        # 3. Check repeat offender status
        is_repeat = self._check_repeat_offender(request.client_ip)
        if is_repeat:
            signals.append(
                ThreatSignal(
                    name="repeat_offender",
                    score=0.3,
                    description="IP has history of suspicious requests",
                    category="history",
                )
            )

        # 4. Message structure analysis
        structure_signals = self._analyze_message_structure(messages)
        signals.extend(structure_signals)

        # 5. Content length analysis
        length_signals = self._analyze_content_lengths(messages, request)
        signals.extend(length_signals)

        # 6. Advanced fingerprint-based analysis
        fingerprint_signals, fingerprint_patterns = self._analyze_fingerprints(
            request, message_contents, system_prompt
        )
        signals.extend(fingerprint_signals)
        all_patterns.extend(fingerprint_patterns)

        # Calculate final threat score
        threat_score = self._calculate_threat_score(signals, all_patterns)

        # Determine threat level
        threat_level = self._score_to_level(threat_score)

        # Determine recommended action
        action = self._determine_action(threat_level, threat_score)

        # Update offender tracking
        if threat_score >= 0.5:
            self._update_offender_score(request.client_ip, threat_score)

        # Update request with threat info
        request.threat_score = threat_score
        request.detected_patterns = [p.pattern_type.value for p in all_patterns]

        # Track the request
        self.tracker.track(request)

        # Build assessment
        return ThreatAssessment(
            request_id=request.request_id,
            threat_score=threat_score,
            threat_level=threat_level,
            recommended_action=action,
            signals=signals,
            patterns=all_patterns,
            is_repeat_offender=is_repeat,
            related_threat_count=len(all_patterns),
            summary=self._generate_summary(threat_level, signals, all_patterns),
            details={
                "signal_count": len(signals),
                "pattern_count": len(all_patterns),
                "blocking_enabled": self.blocking_enabled,
                "would_block": threat_score >= self.blocking_threshold,
            },
        )

    def should_block(self, assessment: ThreatAssessment) -> bool:
        """Determine if request should be blocked based on assessment."""
        if not self.blocking_enabled:
            return False
        return assessment.threat_score >= self.blocking_threshold

    def _extract_contents(self, messages: list[dict[str, Any]]) -> list[str]:
        """Extract text content from messages."""
        contents = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                contents.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        contents.append(part.get("text", ""))
                    elif isinstance(part, str):
                        contents.append(part)
        return contents

    def _extract_system_prompt(self, messages: list[dict[str, Any]]) -> Optional[str]:
        """Extract system prompt from messages."""
        for msg in messages:
            if msg.get("role") == "system":
                content = msg.get("content")
                if isinstance(content, str):
                    return content
                elif isinstance(content, list):
                    texts = [p.get("text", "") for p in content if isinstance(p, dict)]
                    return " ".join(texts)
        return None

    def _analyze_behavior(self, request: TrackedRequest) -> list[ThreatSignal]:
        """Analyze behavioral signals."""
        signals = []

        # Request rate from IP
        rate_60s = self.tracker.get_ip_request_rate(request.client_ip, 60)
        if rate_60s > 5:
            signals.append(
                ThreatSignal(
                    name="high_request_rate",
                    score=min((rate_60s - 5) * 0.1, 0.5),
                    description=f"Elevated request rate: {rate_60s:.1f}/min",
                    category="behavioral",
                    metadata={"rate": rate_60s},
                )
            )

        # Content diversity (many different requests = possible fragmentation)
        unique_content = self.tracker.count_unique_content_from_ip(
            request.client_ip, 300
        )
        if unique_content > 20:
            signals.append(
                ThreatSignal(
                    name="high_content_diversity",
                    score=min((unique_content - 20) * 0.02, 0.4),
                    description=f"High content diversity: {unique_content} unique messages",  # noqa: E501
                    category="behavioral",
                )
            )

        return signals

    def _analyze_message_structure(
        self, messages: list[dict[str, Any]]
    ) -> list[ThreatSignal]:
        """Analyze message structure for suspicious patterns."""
        signals = []

        # Check for unusual message count
        if len(messages) > 50:
            signals.append(
                ThreatSignal(
                    name="excessive_messages",
                    score=min((len(messages) - 50) * 0.01, 0.3),
                    description=f"Unusually long conversation: {len(messages)} messages",  # noqa: E501
                    category="structure",
                )
            )

        # Check for role distribution
        roles = [m.get("role") for m in messages]
        if roles.count("system") > 1:
            signals.append(
                ThreatSignal(
                    name="multiple_system_prompts",
                    score=0.4,
                    description="Multiple system prompts detected (possible injection)",
                    category="structure",
                )
            )

        # Check for alternating pattern violations
        for i in range(1, len(messages)):
            if messages[i].get("role") == messages[i - 1].get("role") == "assistant":
                signals.append(
                    ThreatSignal(
                        name="consecutive_assistant",
                        score=0.2,
                        description="Consecutive assistant messages (unusual structure)",  # noqa: E501
                        category="structure",
                    )
                )
                break

        return signals

    def _analyze_content_lengths(
        self, messages: list[dict[str, Any]], request: TrackedRequest
    ) -> list[ThreatSignal]:
        """Analyze content length patterns."""
        signals = []

        # Very short messages might indicate fragmentation
        contents = self._extract_contents(messages)
        if contents:
            avg_length = sum(len(c) for c in contents) / len(contents)
            if avg_length < 20 and len(contents) > 5:
                signals.append(
                    ThreatSignal(
                        name="short_fragmented_messages",
                        score=0.25,
                        description=f"Very short average message length ({avg_length:.0f} chars)",  # noqa: E501
                        category="structure",
                    )
                )

            # Very long single message might be trying to overflow context
            max_length = max(len(c) for c in contents)
            if max_length > 50000:
                signals.append(
                    ThreatSignal(
                        name="extremely_long_message",
                        score=0.3,
                        description=f"Extremely long message ({max_length} chars)",
                        category="structure",
                    )
                )

        return signals

    def _analyze_fingerprints(
        self,
        request: TrackedRequest,
        message_contents: list[str],
        system_prompt: Optional[str],
    ) -> tuple[list[ThreatSignal], list[AttackPattern]]:
        """
        Perform advanced fingerprint-based analysis.
        Detects similar content, fragments, and coordinated attacks.
        """
        signals = []
        patterns = []

        if not self.fingerprinter or not message_contents:
            return signals, patterns

        # Combine all content for fingerprinting
        full_content = "\n".join(message_contents)
        if system_prompt:
            full_content = f"[SYSTEM]{system_prompt}[/SYSTEM]\n{full_content}"

        # Generate fingerprint
        fp = self.fingerprinter.fingerprint(full_content)

        # Store semantic fingerprint on request
        request.semantic_fingerprint = fp.semantic_hash

        # Check for high entropy (possible encoded/encrypted content)
        if fp.entropy > 5.5:
            signals.append(
                ThreatSignal(
                    name="high_entropy_content",
                    score=min((fp.entropy - 5.5) * 0.2, 0.4),
                    description=f"High entropy content ({fp.entropy:.2f} bits/char) - possible encoding",  # noqa: E501
                    category="fingerprint",
                    metadata={"entropy": fp.entropy},
                )
            )

        # Check for suspicious code patterns
        if fp.code_ratio > 0.15:
            signals.append(
                ThreatSignal(
                    name="high_code_ratio",
                    score=min(fp.code_ratio * 0.5, 0.3),
                    description=f"High code content ratio ({fp.code_ratio:.1%})",
                    category="fingerprint",
                )
            )

        # Check for suspicious entities
        suspicious_entities = [
            e for e in fp.entities if any(t in e for t in ["api_key", "hash", "path"])
        ]
        if suspicious_entities:
            signals.append(
                ThreatSignal(
                    name="suspicious_entities",
                    score=min(len(suspicious_entities) * 0.15, 0.5),
                    description=f"Found {len(suspicious_entities)} suspicious entities",
                    category="fingerprint",
                    metadata={"entities": suspicious_entities[:5]},
                )
            )

        # Find similar previous requests (potential campaign/replay)
        similar_matches = self.fingerprinter.find_similar(
            fp, min_similarity=0.75, max_results=5
        )

        if similar_matches:
            # Filter out self-matches and very recent
            significant_matches = [
                m
                for m in similar_matches
                if m.fingerprint_b != fp.exact_hash and m.similarity_score < 0.99
            ]

            if significant_matches:
                best_match = significant_matches[0]

                signals.append(
                    ThreatSignal(
                        name="similar_content_detected",
                        score=best_match.similarity_score * 0.4,
                        description=f"Similar content found ({best_match.similarity_score:.1%} match)",  # noqa: E501
                        category="fingerprint",
                        metadata={
                            "match_type": best_match.match_type,
                            "matching_features": best_match.matching_features,
                        },
                    )
                )

                if len(significant_matches) >= 3:
                    patterns.append(
                        AttackPattern(
                            pattern_type=AttackPatternType.COORDINATED_CAMPAIGN,
                            confidence=min(0.5 + len(significant_matches) * 0.1, 0.85),
                            severity=0.7,
                            description=f"Content matches {len(significant_matches)} previous requests",  # noqa: E501
                            evidence=[
                                f"Match similarity: {m.similarity_score:.1%}"
                                for m in significant_matches[:3]
                            ],
                            related_requests=[request.request_id],
                            metadata={"match_count": len(significant_matches)},
                        )
                    )

        # Check for semantic evasion (same meaning, different words)
        # This catches paraphrased attack attempts
        if fp.semantic_hash:
            semantic_duplicates = sum(
                1
                for h, cached_fp in self._recent_fingerprints.items()
                if cached_fp.semantic_hash == fp.semantic_hash and h != fp.exact_hash
            )
            if semantic_duplicates >= 2:
                patterns.append(
                    AttackPattern(
                        pattern_type=AttackPatternType.SEMANTIC_EVASION,
                        confidence=min(0.4 + semantic_duplicates * 0.1, 0.8),
                        severity=0.65,
                        description=f"Semantically similar to {semantic_duplicates} previous requests",  # noqa: E501
                        evidence=[f"Semantic hash: {fp.semantic_hash[:8]}..."],
                        related_requests=[request.request_id],
                    )
                )

        # Cache this fingerprint
        self._recent_fingerprints[fp.exact_hash] = fp

        # Cleanup old fingerprints (keep last 1000)
        if len(self._recent_fingerprints) > 1000:
            oldest_keys = sorted(
                self._recent_fingerprints.keys(),
                key=lambda k: self._recent_fingerprints[k].timestamp,
            )[:200]
            for k in oldest_keys:
                del self._recent_fingerprints[k]

        return signals, patterns

    def _check_repeat_offender(self, ip: str) -> bool:
        """Check if IP is a repeat offender."""
        return self._offender_scores.get(ip, 0) >= 0.5

    def _update_offender_score(self, ip: str, score: float) -> None:
        """Update offender score with decay."""
        current = self._offender_scores.get(ip, 0)
        # Exponential moving average
        self._offender_scores[ip] = current * 0.7 + score * 0.3

    def _calculate_threat_score(
        self, signals: list[ThreatSignal], patterns: list[AttackPattern]
    ) -> float:
        """Calculate combined threat score."""
        if not signals and not patterns:
            return 0.0

        # Get pattern-based score
        pattern_score = self.detector.get_combined_threat_score(patterns)

        # Get signal-based score
        signal_scores = sorted([s.score for s in signals], reverse=True)
        signal_score = 0.0
        weight = 1.0
        for score in signal_scores:
            signal_score += score * weight
            weight *= 0.5

        # Combine with weights
        combined = pattern_score * 0.6 + min(signal_score, 1.0) * 0.4

        return min(combined, 1.0)

    def _score_to_level(self, score: float) -> ThreatLevel:
        """Convert numeric score to threat level."""
        if score >= self.THRESHOLDS[ThreatLevel.CRITICAL]:
            return ThreatLevel.CRITICAL
        elif score >= self.THRESHOLDS[ThreatLevel.HIGH]:
            return ThreatLevel.HIGH
        elif score >= self.THRESHOLDS[ThreatLevel.MEDIUM]:
            return ThreatLevel.MEDIUM
        elif score >= self.THRESHOLDS[ThreatLevel.LOW]:
            return ThreatLevel.LOW
        return ThreatLevel.NONE

    def _determine_action(self, level: ThreatLevel, score: float) -> ThreatAction:
        """Determine recommended action based on threat level."""
        base_action = self.ACTION_MAP.get(level, ThreatAction.ALLOW)

        # Override to QUARANTINE for very high scores
        if score >= 0.95:
            return ThreatAction.QUARANTINE

        return base_action

    def _generate_summary(
        self,
        level: ThreatLevel,
        signals: list[ThreatSignal],
        patterns: list[AttackPattern],
    ) -> str:
        """Generate human-readable summary."""
        if level == ThreatLevel.NONE:
            return "No threats detected"

        parts = []
        if patterns:
            pattern_types = set(p.pattern_type.value for p in patterns)
            parts.append(f"Detected patterns: {', '.join(pattern_types)}")

        if signals:
            high_signals = [s for s in signals if s.score >= 0.3]
            if high_signals:
                names = [s.name for s in high_signals[:3]]
                parts.append(f"Key signals: {', '.join(names)}")

        return "; ".join(parts) if parts else f"Threat level: {level.value}"

    def get_stats(self) -> dict[str, Any]:
        """Get analyzer statistics."""
        tracker_stats = self.tracker.get_stats()
        stats = {
            **tracker_stats,
            "tracked_offenders": len(self._offender_scores),
            "blocking_enabled": self.blocking_enabled,
            "blocking_threshold": self.blocking_threshold,
            "fingerprinting_enabled": self.enable_fingerprinting,
            "cached_fingerprints": len(self._recent_fingerprints),
        }

        # Add fingerprinter stats if available
        if self.fingerprinter:
            fp_stats = self.fingerprinter.get_stats()
            stats["fingerprint_total"] = fp_stats.get("total_fingerprints", 0)
            stats["fingerprint_lsh_buckets"] = fp_stats.get("lsh_buckets", 0)

        return stats
