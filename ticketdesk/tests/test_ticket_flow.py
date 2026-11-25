"""Sprawdzenie sesji, szablonów, CSRF i formularzy multipart na testowej bazie SQLite."""
import os
import re
import tempfile
import unittest

_tmp = tempfile.TemporaryDirectory(prefix="ticketdesk-flow-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}/test.db"

from fastapi.testclient import TestClient
from app.main import app, startup_event
from app.database import Base, engine, SessionLocal
from app.models import Attachment, Comment, Ticket


def extract_csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not match:
        raise AssertionError("Brak ukrytego pola csrf_token w formularzu")
    return match.group(1)


class TicketFlowTests(unittest.TestCase):
    def setUp(self):
        # Nigdy nie wykonuj resetu tabel na produkcyjnym PostgreSQL.
        if engine.dialect.name != "sqlite":
            raise RuntimeError("Testy przepływu wymagają odizolowanej bazy SQLite")
        Base.metadata.drop_all(engine)
        startup_event()
        self.employee = TestClient(app, follow_redirects=False)

    def tearDown(self):
        self.employee.close()

    def login(self, client, username, password):
        page = client.get("/login")
        self.assertEqual(page.status_code, 200)
        return client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": extract_csrf(page.text),
            },
        )

    def test_login_ticket_comment_and_attachment(self):
        self.assertEqual(self.employee.get("/login").status_code, 200)
        malformed_login = self.login(self.employee, "x", "a")
        self.assertEqual(malformed_login.status_code, 400)
        invalid_login = self.login(self.employee, "jan.kowalski", "incorrect")
        self.assertEqual(invalid_login.status_code, 401)
        login = self.login(self.employee, "jan.kowalski", "pracownik123")
        self.assertEqual(login.status_code, 303)
        self.assertEqual(login.headers["location"], "/panel/employee")
        panel = self.employee.get("/panel/employee")
        self.assertEqual(panel.status_code, 200)

        attachment_body = b"Diagnostic information for the test ticket."
        created = self.employee.post(
            "/tickets/create",
            data={
                "title": "Problem z testowym stanowiskiem",
                "description": "Po zalogowaniu nie moge otworzyc aplikacji.",
                "category": "Oprogramowanie",
                "priority": "Wysoki",
                "csrf_token": extract_csrf(panel.text),
            },
            files={"attachment": ("diagnostics.txt", attachment_body, "text/plain")},
        )
        self.assertEqual(created.status_code, 303)
        ticket_path = created.headers["location"]
        ticket_id = int(ticket_path.rsplit("/", 1)[1])
        detail = self.employee.get(ticket_path)
        self.assertEqual(detail.status_code, 200)
        self.assertIn("Problem z testowym stanowiskiem", detail.text)

        comment_body = b"Additional diagnostic information."
        commented = self.employee.post(
            f"{ticket_path}/comments",
            data={
                "content": "Dodatkowe informacje do zgloszenia",
                "csrf_token": extract_csrf(detail.text),
            },
            files={"attachment": ("comment.txt", comment_body, "text/plain")},
        )
        self.assertEqual(commented.status_code, 303)
        self.assertEqual(commented.headers["location"], ticket_path)
        self.assertIn(
            "Dodatkowe informacje do zgloszenia", self.employee.get(ticket_path).text
        )

        with SessionLocal() as db:
            ticket = db.get(Ticket, ticket_id)
            self.assertEqual(ticket.status, "Nowy")
            comment = db.query(Comment).filter_by(ticket_id=ticket_id).one()
            attachments = db.query(Attachment).filter_by(ticket_id=ticket_id).all()
            self.assertEqual(len(attachments), 2)
            attachment_ids = {item.filename: item.id for item in attachments}
            self.assertEqual(
                next(
                    item for item in attachments if item.filename == "comment.txt"
                ).comment_id,
                comment.id,
            )

        for filename, expected_body in [
            ("diagnostics.txt", attachment_body),
            ("comment.txt", comment_body),
        ]:
            downloaded = self.employee.get(f"/attachments/{attachment_ids[filename]}")
            self.assertEqual(downloaded.status_code, 200)
            self.assertEqual(downloaded.content, expected_body)
            self.assertTrue(downloaded.headers["content-type"].startswith("text/plain"))

        with TestClient(app, follow_redirects=False) as other_employee:
            self.assertEqual(
                self.login(other_employee, "anna.nowak", "pracownik123").status_code,
                303,
            )
            self.assertEqual(other_employee.get(ticket_path).status_code, 403)
            self.assertEqual(
                other_employee.get(
                    f"/attachments/{attachment_ids['diagnostics.txt']}"
                ).status_code,
                403,
            )
