"""
Request logging middleware for logging all requests to a JSONL file.
"""

import atexit
import json
import logging
import os
from datetime import datetime, timezone
from typing import Callable, TextIO

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs all requests to a JSONL file."""

    _file_handle: TextIO | None = None

    def __init__(self, app, log_file: str | None = None):
        super().__init__(app)
        self.log_file = log_file or os.getenv("LOG_FILE")
        if self.log_file and self._file_handle is None:
            self._open_file()

    def _open_file(self) -> None:
        """Open the log file and register cleanup on exit."""
        if self.log_file:
            try:
                RequestLoggingMiddleware._file_handle = open(self.log_file, "a")
                atexit.register(self._close_file)
                logger.info("Request logging enabled, writing to: %s", self.log_file)
            except OSError as e:
                logger.error("Failed to open log file %s: %s", self.log_file, e)

    @classmethod
    def _close_file(cls) -> None:
        """Close the log file handle."""
        if cls._file_handle:
            cls._file_handle.close()
            cls._file_handle = None

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self._file_handle:
            return await call_next(request)

        logger.info("Processing request: %s %s", request.method, request.url.path)

        # Capture request details
        body = await request.body()

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "headers": dict(request.headers),
            "client_host": request.client.host if request.client else None,
            "client_port": request.client.port if request.client else None,
            "body": body.decode("utf-8", errors="replace") if body else None,
        }

        # Write to persistent file handle and flush
        self._file_handle.write(json.dumps(log_entry) + "\n")
        self._file_handle.flush()

        return await call_next(request)
