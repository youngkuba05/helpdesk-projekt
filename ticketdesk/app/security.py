"""Mechanizmy bezpieczeństwa aplikacji: audyt, rate-limiting, walidacja plików i nagłówki."""
from datetime import datetime, timedelta
import json
import logging
import os
import re
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from .models import SecurityEvent, User


security_logger = logging.getLogger("ticketdesk.security")
if not security_logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    security_logger.addHandler(handler)
security_logger.setLevel(logging.INFO)
security_logger.propagate = False

_SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9._ -]")


def get_client_ip(request: Request, trust_proxy_headers: bool) -> str:
    if trust_proxy_headers:
        forwarded_for = request.headers.get("x-forwarded-for", "")
        if forwarded_for:
            first_hop = forwarded_for.split(",")[0].strip()
            if first_hop:
                return first_hop[:64]
    if request.client and request.client.host:
        return request.client.host[:64]
    return "unknown"


def get_user_agent(request: Request) -> str:
    return (request.headers.get("user-agent") or "unknown").strip()[:255]


def is_https_request(request: Request, trust_proxy_headers: bool) -> bool:
    if request.url.scheme == "https":
        return True
    if trust_proxy_headers:
        proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
        return proto == "https"
    return False


def emit_security_log(
    event_type: str,
    severity: str,
    username: Optional[str] = None,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    path: Optional[str] = None,
    details: Optional[str] = None,
) -> None:
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "severity": severity,
        "user_id": user_id,
        "username": username,
        "ip_address": ip_address,
        "path": path,
        "details": details,
    }
    security_logger.info(json.dumps(payload, ensure_ascii=False))


def record_security_event(
    db: Session,
    event_type: str,
    severity: str = "INFO",
    request: Optional[Request] = None,
    trust_proxy_headers: bool = False,
    user: Optional[User] = None,
    username: Optional[str] = None,
    details: Optional[str] = None,
) -> None:
    ip_address = (
        get_client_ip(request, trust_proxy_headers) if request is not None else None
    )
    path = request.url.path[:255] if request is not None else None
    resolved_username = username or (user.username if user else None)
    resolved_user_id = user.id if user else None

    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        user_id=resolved_user_id,
        username=resolved_username[:50] if resolved_username else None,
        ip_address=ip_address,
        path=path,
        details=details[:500] if details else None,
    )
    db.add(event)
    db.commit()

    emit_security_log(
        event_type=event_type,
        severity=severity,
        username=resolved_username,
        user_id=resolved_user_id,
        ip_address=ip_address,
        path=path,
        details=details,
    )


def is_login_rate_limited(
    db: Session,
    username: str,
    ip_address: str,
    window_seconds: int,
    max_attempts_per_user: int,
    max_attempts_per_ip: int,
) -> bool:
    cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)

    user_failures = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type == "login_failed",
            SecurityEvent.username == username,
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= cutoff,
        )
        .count()
    )
    if user_failures >= max_attempts_per_user:
        return True

    ip_failures = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type == "login_failed",
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= cutoff,
        )
        .count()
    )
    return ip_failures >= max_attempts_per_ip


def sanitize_filename(filename: str) -> str:
    base = os.path.basename(filename or "").strip()
    cleaned = _SAFE_FILENAME_RE.sub("_", base).strip(". ")
    return (cleaned or "attachment")[:200]


def validate_magic_bytes(raw_bytes: bytes, declared_mime: str) -> bool:
    if declared_mime == "image/png":
        return raw_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    if declared_mime == "image/jpeg":
        return raw_bytes.startswith(b"\xff\xd8\xff")
    if declared_mime == "image/gif":
        return raw_bytes.startswith((b"GIF87a", b"GIF89a"))
    if declared_mime == "image/webp":
        return (
            len(raw_bytes) >= 12
            and raw_bytes[:4] == b"RIFF"
            and raw_bytes[8:12] == b"WEBP"
        )
    if declared_mime == "application/pdf":
        return raw_bytes.startswith(b"%PDF-")
    if declared_mime == "text/plain":
        if b"\x00" in raw_bytes:
            return False
        try:
            raw_bytes.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False
    return False
