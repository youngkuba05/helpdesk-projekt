"""Integracyjne testy panelu na odizolowanej bazie SQLite."""
import os
import re
import tempfile
import unittest

_tmp = tempfile.TemporaryDirectory(prefix="ticketdesk-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}/test.db"

from fastapi.testclient import TestClient
from sqlalchemy import text, inspect
from app.main import app, startup_event, pwd_context, SESSION_COOKIE_NAME
from app.database import Base, engine, SessionLocal
from app.models import User, Ticket


class UserManagementTests(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine)
        startup_event()
        self.admin = TestClient(app, follow_redirects=False)
        self.login(self.admin, "admin.helpdesk", "agent123")

    def tearDown(self):
        self.admin.close()

    def login(self, client, username, password):
        return client.post("/login", data={"username": username, "password": password})

    def token(self, path="/admin/users/new"):
        page = self.admin.get(path)
        self.assertEqual(page.status_code, 200)
        return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)

    def create(self, **changes):
        data = dict(username="test.user", full_name="Test User", password="testpass123",
                    role="employee", is_active="true", csrf_token=self.token())
        data.update(changes)
        return self.admin.post("/admin/users/new", data=data)

    def account(self, username="test.user"):
        with SessionLocal() as db:
            return db.query(User).filter_by(username=username).one()

    def edit(self, account, **changes):
        data = dict(username=account.username, full_name=account.full_name, role=account.role,
                    is_active="true", password="", csrf_token=self.token())
        data.update(changes)
        return self.admin.post(f"/admin/users/{account.id}/edit", data=data)

    def test_creation_login_and_admin_ticket_access(self):
        self.assertEqual(self.create().status_code, 303)
        account = self.account()
        self.assertNotEqual(account.password_hash, "testpass123")
        self.assertTrue(pwd_context.verify("testpass123", account.password_hash))
        with TestClient(app, follow_redirects=False) as employee:
            self.assertEqual(self.login(employee, "test.user", "testpass123").status_code, 303)
            self.assertEqual(employee.get("/panel/employee").status_code, 200)
        self.assertIn("test.user", self.admin.get("/admin/users").text)
        self.assertEqual(self.admin.get("/panel/agent").status_code, 200)
        self.assertEqual(self.admin.get("/tickets/1").status_code, 200)
        self.assertEqual(self.admin.post("/tickets/1/status", data={"new_status": "Rozwiązany"}).status_code, 303)

    def test_access_control_and_csrf(self):
        for username, password in [("jan.kowalski", "pracownik123"), ("agent.it", "agent123")]:
            with TestClient(app, follow_redirects=False) as client:
                self.login(client, username, password)
                for path in ["/admin/users", "/admin/users/new", "/admin/users/1/edit"]:
                    self.assertEqual(client.get(path).status_code, 403)
                for path in ["/admin/users/new", "/admin/users/1/edit"]:
                    self.assertEqual(client.post(path, data={}).status_code, 403)
        with TestClient(app, follow_redirects=False) as anonymous:
            self.assertEqual(anonymous.get("/admin/users").status_code, 303)
        self.assertEqual(self.create(csrf_token="wrong").status_code, 403)

    def test_validation_duplicates_and_missing_user(self):
        self.assertEqual(self.create().status_code, 303)
        for changes in [dict(username="TEST.USER"), dict(username="test.user")]:
            self.assertEqual(self.create(**changes).status_code, 409)
        for changes in [dict(username="bad login"), dict(full_name="   "), dict(role="root"),
                        dict(password="short"), dict(password=""), dict(password="ą" * 37)]:
            self.assertEqual(self.create(**changes).status_code, 400)
        self.assertEqual(self.admin.get("/admin/users/999/edit").status_code, 404)
        self.assertEqual(self.admin.post("/admin/users/999/edit", data={}).status_code, 404)

    def test_edit_password_role_and_session_revocation(self):
        self.create()
        account = self.account()
        with TestClient(app, follow_redirects=False) as client:
            self.login(client, "test.user", "testpass123")
            self.assertEqual(self.edit(account, full_name="Updated User", role="agent").status_code, 303)
            self.assertEqual(client.get("/panel/employee").status_code, 303)
            self.assertEqual(client.get("/panel/employee").headers["location"], "/login")
            self.login(client, "test.user", "testpass123")
            self.assertEqual(client.get("/panel/agent").status_code, 200)
            account = self.account()
            self.assertEqual(account.full_name, "Updated User")
            self.assertEqual(self.edit(account, password="newpassword123").status_code, 303)
            self.assertEqual(client.get("/panel/agent").headers["location"], "/login")
            self.assertEqual(self.login(client, "test.user", "testpass123").status_code, 401)
            self.assertEqual(self.login(client, "test.user", "newpassword123").status_code, 303)

    def test_block_reactivate_history_and_self_protection(self):
        account = self.account("jan.kowalski")
        with TestClient(app, follow_redirects=False) as client:
            self.login(client, account.username, "pracownik123")
            old_cookie = client.cookies.get(SESSION_COOKIE_NAME)
            self.assertEqual(self.edit(account, is_active="false").status_code, 303)
            self.assertEqual(client.get("/panel/employee").headers["location"], "/login")
            self.assertEqual(self.login(client, account.username, "pracownik123").status_code, 401)
            with SessionLocal() as db:
                self.assertEqual(db.query(Ticket).filter_by(creator_id=account.id).count(), 1)
            self.assertEqual(self.edit(self.account(account.username)).status_code, 303)
            client.cookies.set(SESSION_COOKIE_NAME, old_cookie)
            self.assertEqual(client.get("/panel/employee").headers["location"], "/login")
            self.assertEqual(self.login(client, account.username, "pracownik123").status_code, 303)
        admin = self.account("admin.helpdesk")
        self.assertEqual(self.edit(admin, role="employee").status_code, 400)
        self.assertEqual(self.edit(admin, is_active="false").status_code, 400)

    def test_existing_database_migration_is_repeatable(self):
        Base.metadata.drop_all(engine)
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, full_name VARCHAR(100) NOT NULL, password_hash VARCHAR(255) NOT NULL, role VARCHAR(20) NOT NULL)"))
            connection.execute(text("INSERT INTO users VALUES (1, 'admin.helpdesk', 'Existing Admin', 'existing-hash', 'agent')"))
        startup_event()
        startup_event()
        account = self.account("admin.helpdesk")
        self.assertEqual(account.role, "admin")
        self.assertTrue(account.is_active)
        self.assertEqual(account.session_version, 0)
        self.assertEqual(account.password_hash, "existing-hash")
        self.assertIn("is_active", {c["name"] for c in inspect(engine).get_columns("users")})
