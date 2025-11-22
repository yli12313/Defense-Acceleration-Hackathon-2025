"""
Request Tracker for OpenSafety AI.
Tracks requests across multiple dimensions for correlation and attack detection.
"""

import hashlib  # noqa: I001
import time
import threading
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime  # noqa: F401


@dataclass
class TrackedRequest:
    """A tracked API request with all relevant metadata."""

    request_id: str
    timestamp: float

    # Client identification
    client_ip: str
    user_id: Optional[str] = None
    api_key_hash: Optional[str] = None  # Hashed for privacy

    # Request metadata
    model: str = ""
    message_count: int = 0
    total_content_length: int = 0
    has_system_prompt: bool = False
    has_tools: bool = False
    tool_count: int = 0

    # Content fingerprints (for correlation)
    content_hash: str = ""  # Hash of message contents
    system_prompt_hash: Optional[str] = None
    semantic_fingerprint: Optional[str] = None  # For similar content detection

    # Extracted signals
    detected_patterns: list[str] = field(default_factory=list)
    extracted_entities: list[str] = field(
        default_factory=list
    )  # URLs, IPs, code snippets  # noqa: E501

    # Response metadata
    response_tokens: int = 0
    response_time_ms: float = 0.0
    was_blocked: bool = False
    threat_score: float = 0.0


class RequestTracker:
    """
    High-performance request tracker for detecting split-up attacks.

    Maintains sliding windows of requests indexed by multiple dimensions:
    - Client IP
    - User ID / API Key
    - Content similarity
    - Temporal clustering

    Designed to handle millions of requests with efficient memory usage.
    """

    def __init__(
        self,
        window_size_seconds: int = 300,  # 5 minute default window
        max_requests_per_key: int = 1000,
        cleanup_interval_seconds: int = 60,
    ):
        self.window_size = window_size_seconds
        self.max_requests_per_key = max_requests_per_key
        self.cleanup_interval = cleanup_interval_seconds

        # Request storage indexed by different dimensions
        self._by_ip: dict[str, deque[TrackedRequest]] = defaultdict(
            lambda: deque(maxlen=max_requests_per_key)
        )  # noqa: E501
        self._by_user: dict[str, deque[TrackedRequest]] = defaultdict(
            lambda: deque(maxlen=max_requests_per_key)
        )  # noqa: E501
        self._by_api_key: dict[str, deque[TrackedRequest]] = defaultdict(
            lambda: deque(maxlen=max_requests_per_key)
        )  # noqa: E501
        self._by_content_hash: dict[str, deque[TrackedRequest]] = defaultdict(
            lambda: deque(maxlen=100)
        )  # noqa: E501
        self._by_system_hash: dict[str, deque[TrackedRequest]] = defaultdict(
            lambda: deque(maxlen=500)
        )  # noqa: E501

        # Global recent requests for burst detection
        self._recent_all: deque[TrackedRequest] = deque(maxlen=10000)

        # Aggregate statistics
        self._stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "unique_ips": set(),
            "unique_users": set(),
        }

        # Thread safety
        self._lock = threading.RLock()

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_running = True
        self._cleanup_thread.start()

    def track(self, request: TrackedRequest) -> None:
        """Add a request to all tracking indices."""
        with self._lock:
            now = time.time()
            request.timestamp = now

            # Index by IP
            self._by_ip[request.client_ip].append(request)

            # Index by user if available
            if request.user_id:
                self._by_user[request.user_id].append(request)

            # Index by API key hash
            if request.api_key_hash:
                self._by_api_key[request.api_key_hash].append(request)

            # Index by content hash for duplicate/fragment detection
            if request.content_hash:
                self._by_content_hash[request.content_hash].append(request)

            # Index by system prompt for campaign detection
            if request.system_prompt_hash:
                self._by_system_hash[request.system_prompt_hash].append(request)

            # Add to global recent
            self._recent_all.append(request)

            # Update stats
            self._stats["total_requests"] += 1
            self._stats["unique_ips"].add(request.client_ip)
            if request.user_id:
                self._stats["unique_users"].add(request.user_id)
            if request.was_blocked:
                self._stats["blocked_requests"] += 1

    def get_requests_by_ip(
        self, ip: str, window_seconds: Optional[int] = None
    ) -> list[TrackedRequest]:  # noqa: E501
        """Get recent requests from an IP within the time window."""
        return self._get_recent(self._by_ip.get(ip, deque()), window_seconds)

    def get_requests_by_user(
        self, user_id: str, window_seconds: Optional[int] = None
    ) -> list[TrackedRequest]:  # noqa: E501
        """Get recent requests from a user within the time window."""
        return self._get_recent(self._by_user.get(user_id, deque()), window_seconds)

    def get_requests_by_api_key(
        self, api_key_hash: str, window_seconds: Optional[int] = None
    ) -> list[TrackedRequest]:  # noqa: E501
        """Get recent requests from an API key within the time window."""
        return self._get_recent(
            self._by_api_key.get(api_key_hash, deque()), window_seconds
        )  # noqa: E501

    def get_requests_by_content(
        self, content_hash: str, window_seconds: Optional[int] = None
    ) -> list[TrackedRequest]:  # noqa: E501
        """Get requests with matching content hash."""
        return self._get_recent(
            self._by_content_hash.get(content_hash, deque()), window_seconds
        )  # noqa: E501

    def get_requests_by_system_prompt(
        self, system_hash: str, window_seconds: Optional[int] = None
    ) -> list[TrackedRequest]:  # noqa: E501
        """Get requests using the same system prompt (campaign detection)."""
        return self._get_recent(
            self._by_system_hash.get(system_hash, deque()), window_seconds
        )  # noqa: E501

    def get_recent_requests(
        self, window_seconds: Optional[int] = None, limit: int = 1000
    ) -> list[TrackedRequest]:  # noqa: E501
        """Get all recent requests within the time window."""
        requests = self._get_recent(self._recent_all, window_seconds)
        return requests[-limit:] if len(requests) > limit else requests

    def get_ip_request_rate(self, ip: str, window_seconds: int = 60) -> float:
        """Get requests per second from an IP over the window."""
        requests = self.get_requests_by_ip(ip, window_seconds)
        if not requests:
            return 0.0
        return len(requests) / window_seconds

    def get_global_request_rate(self, window_seconds: int = 60) -> float:
        """Get global requests per second over the window."""
        requests = self.get_recent_requests(window_seconds)
        if not requests:
            return 0.0
        return len(requests) / window_seconds

    def count_unique_ips_for_content(
        self, content_hash: str, window_seconds: Optional[int] = None
    ) -> int:  # noqa: E501
        """Count unique IPs sending same content (distributed attack detection)."""
        requests = self.get_requests_by_content(content_hash, window_seconds)
        return len(set(r.client_ip for r in requests))

    def count_unique_content_from_ip(
        self, ip: str, window_seconds: Optional[int] = None
    ) -> int:  # noqa: E501
        """Count unique content hashes from an IP (fragmentation detection)."""
        requests = self.get_requests_by_ip(ip, window_seconds)
        return len(set(r.content_hash for r in requests if r.content_hash))

    def get_stats(self) -> dict[str, Any]:
        """Get aggregate statistics."""
        with self._lock:
            return {
                "total_requests": self._stats["total_requests"],
                "blocked_requests": self._stats["blocked_requests"],
                "unique_ips": len(self._stats["unique_ips"]),
                "unique_users": len(self._stats["unique_users"]),
                "tracked_ips": len(self._by_ip),
                "tracked_users": len(self._by_user),
                "tracked_content_hashes": len(self._by_content_hash),
                "tracked_system_prompts": len(self._by_system_hash),
            }

    def _get_recent(
        self, queue: deque, window_seconds: Optional[int] = None
    ) -> list[TrackedRequest]:  # noqa: E501
        """Get items from queue within time window."""
        window = window_seconds or self.window_size
        cutoff = time.time() - window

        with self._lock:
            return [r for r in queue if r.timestamp >= cutoff]

    def _cleanup_loop(self) -> None:
        """Periodically clean up old entries."""
        while self._cleanup_running:
            time.sleep(self.cleanup_interval)
            self._cleanup_old_entries()

    def _cleanup_old_entries(self) -> None:
        """Remove entries outside the window."""
        cutoff = time.time() - self.window_size

        with self._lock:
            # Clean each index
            for index in [
                self._by_ip,
                self._by_user,
                self._by_api_key,
                self._by_content_hash,
                self._by_system_hash,
            ]:
                empty_keys = []
                for key, queue in index.items():
                    # Remove old entries from front of queue
                    while queue and queue[0].timestamp < cutoff:
                        queue.popleft()
                    if not queue:
                        empty_keys.append(key)

                # Remove empty keys
                for key in empty_keys:
                    del index[key]

            # Clean global recent
            while self._recent_all and self._recent_all[0].timestamp < cutoff:
                self._recent_all.popleft()

    def shutdown(self) -> None:
        """Stop the cleanup thread."""
        self._cleanup_running = False
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2)


def hash_content(content: str) -> str:
    """Create a stable hash of content for deduplication."""
    # Normalize whitespace and case for more robust matching
    normalized = " ".join(content.lower().split())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def hash_api_key(api_key: str) -> str:
    """Hash API key for privacy-preserving tracking."""
    return hashlib.sha256(api_key.encode()).hexdigest()[:16]


def create_request_id() -> str:
    """Create a unique request ID."""
    return f"req_{uuid.uuid4().hex}"
