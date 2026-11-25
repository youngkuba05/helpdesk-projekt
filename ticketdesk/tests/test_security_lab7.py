"""Testy mechanizmów bezpieczeństwa LAB7: nagłówki, CSRF, monitoring sesji, rate limit, pliki."""
import os
import re
import tempfile
import unittest

_tmp = tempfile.TemporaryDirectory(prefix="ticketdesk-lab7-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}/test.db"

from fastapi.testclient import TestClient
from app.main import app, startup_event, SESSION_COOKIE_NAME
from app.database import Base, engine, SessionLocal
from app.models import SecurityEvent, UserSession


def extract_csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not match:
        raise AssertionError("Brak ukrytego pola csrf_token w formularzu")
    return match.group(1)


class SecurityLab7Tests(unittest.TestCase):
    def setUp(self):
        if engine.dialect.name != "sqlite":
            raise RuntimeError("Testy wymagają odizolowanej bazy SQLite")
        Base.metadata.drop_all(engine)
        startup_event()

    def login(self, client, username, password):
        page = client.get("/login")
        return client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": extract_csrf(page.text),
            },
        )

    def test_security_headers_and_health_endpoint(self):
        with TestClient(app, follow_redirects=False) as client:
            response = client.get("/login")
            self.assertEqual(response.status_code, 200)
            self.assertIn("default-src 'self'", response.headers["content-security-policy"])
            self.assertNotIn("content-security-policy-report-only", response.headers)
            self.assertEqual(response.headers["x-frame-options"], "DENY")
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertEqual(
                response.headers["referrer-policy"], "strict-origin-when-cross-origin"
            )
            self.assertEqual(
                response.headers["cross-origin-opener-policy"], "same-origin"
            )
            self.assertEqual(
                response.headers["cross-origin-embedder-policy"], "require-corp"
            )
            self.assertEqual(
                response.headers["cross-origin-resource-policy"], "same-origin"
            )
            self.assertIn("no-store", response.headers["cache-control"])

            health = client.get("/health")
            self.assertEqual(health.status_code, 200)
            self.assertEqual(health.json(), {"status": "ok"})

    def test_csrf_protection_blocks_missing_tokens(self):
        with TestClient(app, follow_redirects=False) as client:
            bad_login = client.post(
                "/login", data={"username": "jan.kowalski", "password": "incorrect"}
            )
            self.assertEqual(bad_login.status_code, 403)

            self.assertEqual(
                self.login(client, "agent.it", "agent123").status_code, 303
            )
            self.assertEqual(
                client.post(
                    "/tickets/1/status", data={"new_status": "Rozwiązany"}
                ).status_code,
                403,
            )
            self.assertEqual(client.post("/logout", data={}).status_code, 403)

    def test_server_side_logout_and_session_anomaly_detection(self):
        with TestClient(app, follow_redirects=False) as client:
            client.headers["User-Agent"] = "TicketDeskTestBrowser/1.0"
            self.assertEqual(
                self.login(client, "agent.it", "agent123").status_code, 303
            )
            cookie_val = client.cookies.get(SESSION_COOKIE_NAME)
            sessions_page = client.get("/sessions")
            self.assertEqual(sessions_page.status_code, 200)
            self.assertIn("TicketDeskTestBrowser/1.0", sessions_page.text)

            # Wylogowanie unieważnia sesję w bazie (stare ciasteczko przestaje działać)
            logout_resp = client.post(
                "/logout", data={"csrf_token": extract_csrf(sessions_page.text)}
            )
            self.assertEqual(logout_resp.status_code, 303)
            client.cookies.set(SESSION_COOKIE_NAME, cookie_val)
            self.assertEqual(client.get("/panel/agent").status_code, 303)

            # Zmiana User-Agent w trakcie sesji unieważnia sesję i rejestruje anomalię
            self.assertEqual(
                self.login(client, "agent.it", "agent123").status_code, 303
            )
            client.headers["User-Agent"] = "HijackedBrowser/9.9"
            self.assertEqual(client.get("/panel/agent").status_code, 303)
            with SessionLocal() as db:
                anomalies = (
                    db.query(SecurityEvent)
                    .filter_by(event_type="session_anomaly")
                    .count()
                )
                self.assertGreaterEqual(anomalies, 1)

    def test_login_rate_limiting(self):
        with TestClient(app, follow_redirects=False) as client:
            for _ in range(5):
                resp = self.login(client, "jan.kowalski", "wrong-pass")
                self.assertEqual(resp.status_code, 401)
            blocked = self.login(client, "jan.kowalski", "wrong-pass")
            self.assertEqual(blocked.status_code, 429)

    def test_attachment_magic_bytes_validation(self):
        with TestClient(app, follow_redirects=False) as client:
            self.assertEqual(
                self.login(client, "agent.it", "agent123").status_code, 303
            )
            detail = client.get("/tickets/1")
            spoofed = client.post(
                "/tickets/1/comments",
                data={
                    "content": "Próba przesłania fałszywego PNG",
                    "csrf_token": extract_csrf(detail.text),
                },
                files={
                    "attachment": (
                        "fake.png",
                        b"<script>alert(1)</script>",
                        "image/png",
                    )
                },
            )
            self.assertEqual(spoofed.status_code, 303)
            self.assertIn("error=", spoofed.headers["location"])
            with SessionLocal() as db:
                rejected = (
                    db.query(SecurityEvent)
                    .filter_by(event_type="attachment_rejected")
                    .count()
                )
                self.assertEqual(rejected, 1)

    def test_admin_security_panel_and_remote_session_revocation(self):
        with TestClient(app, follow_redirects=False) as agent_client, TestClient(
            app, follow_redirects=False
        ) as admin_client:
            self.assertEqual(
                self.login(agent_client, "agent.it", "agent123").status_code, 303
            )
            self.assertEqual(agent_client.get("/admin/security").status_code, 403)

            self.assertEqual(
                self.login(admin_client, "admin.helpdesk", "agent123").status_code, 303
            )
            sec_page = admin_client.get("/admin/security")
            self.assertEqual(sec_page.status_code, 200)
            self.assertIn("agent.it", sec_page.text)

            with SessionLocal() as db:
                agent_session = (
                    db.query(UserSession)
                    .filter(UserSession.revoked_at.is_(None))
                    .all()
                )
                target_sid = next(
                    s.id for s in agent_session if s.user.username == "agent.it"
                )

            revoked = admin_client.post(
                f"/admin/sessions/{target_sid}/revoke",
                data={"csrf_token": extract_csrf(sec_page.text)},
            )
            self.assertEqual(revoked.status_code, 303)
            self.assertEqual(agent_client.get("/panel/agent").status_code, 303)
