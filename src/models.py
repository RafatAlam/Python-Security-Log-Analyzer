"""Shared types used throughout the analyzer."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    username: str
    ip: str
    status: str
