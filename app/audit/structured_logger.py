"""
Structured JSON logging for application logs.

Standard stdout/stderr logs are formatted as single-line JSON records.
This facilitates seamless log collection and parsing in Kubernetes environments
by tools such as Fluentbit, Logstash, Vector, or Datadog Agent.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """
    Python Logging Formatter that outputs logs in structured JSON format.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Standard structured fields
        log_record = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }

        # Extract extra fields added directly or via logging adapters
        # (excluding standard LogRecord properties)
        standard_attrs = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
        }
        for key, val in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                log_record[key] = val

        # Format exception stack traces cleanly
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_record, default=str)


def setup_structured_logging(level: int = logging.INFO) -> None:
    """
    Configure the root logger to output structured JSON logs to stdout.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers to prevent duplicate logs
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    # Output to stdout
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root_logger.addHandler(handler)

    # Disable propagation on third-party loggers if they spam, or set their levels
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
