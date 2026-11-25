from datetime import datetime, timedelta
import hmac
import json
import os
import secrets
from typing import Optional
from urllib.parse import quote

from fastapi import (
    FastAPI,
    Request,
    Depends,
    Form,
    UploadFile,
    File,
    HTTPException,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from passlib.context import CryptContext
from pydantic import ValidationError
from sqlalchemy import inspect, text, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .database import engine, SessionLocal, get_db, Base
from .models import User, UserSession, SecurityEvent, Ticket, Comment, Attachment
from .schemas import (
    LoginInput,
    TicketCreateInput,
    CommentCreateInput,
    StatusUpdateInput,
    ALLOWED_CATEGORIES,
    ALLOWED_PRIORITIES,
    ALLOWED_STATUSES,
    UserInput,
    USER_ROLES,
)
from .security import (
    emit_security_log,
    get_client_ip,
    get_user_agent,
    is_https_request,
    is_login_rate_limited,
    record_security_event,
    sanitize_filename,
    validate_magic_bytes,
)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"
ENABLE_DOCS = _env_bool("ENABLE_DOCS", not IS_PRODUCTION)
SHOW_DEMO_ACCOUNTS = _env_bool("SHOW_DEMO_ACCOUNTS", not IS_PRODUCTION)
TRUST_PROXY_HEADERS = _env_bool("TRUST_PROXY_HEADERS", IS_PRODUCTION)
COOKIE_SECURE_DEFAULT = _env_bool("COOKIE_SECURE", IS_PRODUCTION)
ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("ALLOWED_HOSTS", "*").split(",")
    if host.strip()
]

# Parametry sesji i ochrony przed brute-force
SESSION_MAX_AGE_SECONDS = int(os.getenv("SESSION_MAX_AGE_SECONDS", "28800"))  # 8 h
SESSION_IDLE_TIMEOUT_SECONDS = int(
    os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "1800")
)  # 30 min
CSRF_MAX_AGE_SECONDS = int(os.getenv("CSRF_MAX_AGE_SECONDS", "7200"))  # 2 h
SESSION_BIND_UA = _env_bool("SESSION_BIND_UA", True)
SESSION_BIND_IP = _env_bool("SESSION_BIND_IP", False)
LOGIN_RATE_LIMIT_WINDOW = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW", "900"))  # 15 min
LOGIN_MAX_ATTEMPTS_USER = int(os.getenv("LOGIN_MAX_ATTEMPTS_USER", "5"))
LOGIN_MAX_ATTEMPTS_IP = int(os.getenv("LOGIN_MAX_ATTEMPTS_IP", "20"))

app = FastAPI(
    title="TicketDesk - IT Service Desk",
    description="Wewnętrzny system obsługi zgłoszeń i komunikacji serwisowej IT",
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "report-uri /csp-report"
    )

    if IS_PRODUCTION or is_https_request(request, TRUST_PROXY_HEADERS):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=3600"
    else:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"

    return response


@app.get("/health", include_in_schema=False)
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(status_code=503, content={"status": "error"})
    return {"status": "ok"}


@app.post("/csp-report", include_in_schema=False)
async def receive_csp_report(request: Request):
    body = await request.body()
    snippet = ""
    if body:
        try:
            parsed = json.loads(body[:4096].decode("utf-8", errors="replace"))
            report = parsed.get("csp-report", parsed) if isinstance(parsed, dict) else {}
            if isinstance(report, dict):
                snippet = (
                    f"blocked={report.get('blocked-uri', '')}; "
                    f"directive={report.get('violated-directive', '')}"
                )
        except ValueError:
            snippet = "malformed-csp-report"
    emit_security_log(
        event_type="csp_violation",
        severity="WARNING",
        ip_address=get_client_ip(request, TRUST_PROXY_HEADERS),
        path=request.url.path,
        details=snippet[:300] or "empty-csp-report",
    )
    return Response(status_code=204)


# Montowanie plików statycznych i szablonów Jinja2 (SSR)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount(
    "/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static"
)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Konfiguracja podpisywania ciasteczek sesyjnych, tokenów CSRF i hashowania
_env_secret_key = os.getenv("SECRET_KEY", "").strip()
if IS_PRODUCTION and len(_env_secret_key) < 32:
    raise RuntimeError(
        "Zmienna środowiskowa SECRET_KEY (min. 32 znaki) jest wymagana w produkcji."
    )
SECRET_KEY = _env_secret_key or secrets.token_hex(32)

SESSION_COOKIE_NAME = "ticketdesk_session"
CSRF_COOKIE_NAME = "ticketdesk_csrf"
session_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="session-cookie-v2")
csrf_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="csrf-token-v2")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Hash pomocniczy do wyrównania czasu odpowiedzi przy nieistniejących kontach
_DUMMY_BCRYPT_HASH = pwd_context.hash(secrets.token_urlsafe(16))

# Restrykcje załączników (walidacja rozmiaru, MIME i sygnatur binarnych)
MAX_ATTACHMENT_SIZE_MB = int(os.getenv("MAX_ATTACHMENT_SIZE_MB", "5"))
MAX_ATTACHMENT_BYTES = MAX_ATTACHMENT_SIZE_MB * 1024 * 1024
ALLOWED_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "text/plain",
    "application/pdf",
}


# --- INICJALIZACJA BAZY I DANYCH TESTOWYCH W ŚRODOWISKU DEV ---
@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)
    # Uzupełnienie istniejących instalacji bez usuwania danych.
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    with engine.begin() as connection:
        if "is_active" not in columns:
            connection.execute(
                text(
                    "ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE"
                )
            )
        if "session_version" not in columns:
            connection.execute(
                text(
                    "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0"
                )
            )
        # Jednorazowa migracja wbudowanego konta administratora.
        if "is_active" not in columns:
            connection.execute(
                text(
                    "UPDATE users SET role = 'admin' WHERE username = 'admin.helpdesk' AND role = 'agent'"
                )
            )
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            users = [
                User(
                    username="jan.kowalski",
                    full_name="Jan Kowalski (Dział Finansów)",
                    password_hash=pwd_context.hash("pracownik123"),
                    role="employee",
                ),
                User(
                    username="anna.nowak",
                    full_name="Anna Nowak (Dział HR)",
                    password_hash=pwd_context.hash("pracownik123"),
                    role="employee",
                ),
                User(
                    username="agent.it",
                    full_name="Jakub Brzostowski (Wsparcie IT)",
                    password_hash=pwd_context.hash("agent123"),
                    role="agent",
                ),
                User(
                    username="admin.helpdesk",
                    full_name="Stanisław Rajm (Administrator IT)",
                    password_hash=pwd_context.hash("agent123"),
                    role="admin",
                ),
            ]
            db.add_all(users)
            db.commit()

            # Przykładowe zgłoszenie startowe w środowisku DEV
            emp = db.query(User).filter(User.username == "jan.kowalski").first()
            agent = db.query(User).filter(User.username == "agent.it").first()
            sample_ticket = Ticket(
                title="Brak dostępu do firmowego VPN po aktualizacji systemu",
                description="Po dzisiejszej aktualizacji systemu klient VPN zwraca błąd autoryzacji certyfikatu. Proszę o pilną weryfikację.",
                category="Sieć i VPN",
                priority="Wysoki",
                status="W trakcie",
                creator_id=emp.id,
                assigned_agent_id=agent.id,
            )
            db.add(sample_ticket)
            db.commit()
            db.refresh(sample_ticket)

            sample_comment = Comment(
                ticket_id=sample_ticket.id,
                author_id=agent.id,
                content="Cześć Janie, zweryfikowałem logi bramy VPN. Załącz proszę zrzut ekranu z komunikatem błędu z klienta OpenVPN.",
            )
            db.add(sample_comment)
            db.commit()
    finally:
        db.close()


# --- FUNKCJE POMOCNICZE SESJI, CSRF I AUTORYZACJI ---
def _should_use_secure_cookie(request: Request) -> bool:
    return COOKIE_SECURE_DEFAULT or is_https_request(request, TRUST_PROXY_HEADERS)


def create_anon_csrf_token(nonce: str) -> str:
    return csrf_serializer.dumps({"scope": "anon", "nonce": nonce})


def verify_anon_csrf_token(request: Request, token: str, db: Session) -> bool:
    cookie_nonce = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not cookie_nonce or not token:
        record_security_event(
            db,
            "csrf_failed",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            details="Brak tokenu lub ciasteczka CSRF przy logowaniu",
        )
        return False
    try:
        payload = csrf_serializer.loads(token, max_age=CSRF_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        record_security_event(
            db,
            "csrf_failed",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            details="Nieprawidłowy lub wygasły token CSRF przy logowaniu",
        )
        return False
    valid = (
        isinstance(payload, dict)
        and payload.get("scope") == "anon"
        and isinstance(payload.get("nonce"), str)
        and hmac.compare_digest(payload["nonce"], cookie_nonce)
    )
    if not valid:
        record_security_event(
            db,
            "csrf_failed",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            details="Niezgodność tokenu CSRF z ciasteczkiem przy logowaniu",
        )
    return valid


def create_auth_csrf_token(request: Request, user: User) -> str:
    session_id = getattr(request.state, "session_id", "")
    return csrf_serializer.dumps(
        {
            "scope": "auth",
            "user_id": user.id,
            "session_id": session_id,
            "session_version": user.session_version,
        }
    )


def verify_auth_csrf(request: Request, token: str, user: User, db: Session) -> None:
    session_id = getattr(request.state, "session_id", "")
    expected = {
        "scope": "auth",
        "user_id": user.id,
        "session_id": session_id,
        "session_version": user.session_version,
    }
    try:
        payload = csrf_serializer.loads(token, max_age=CSRF_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        record_security_event(
            db,
            "csrf_failed",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details="Nieprawidłowy lub wygasły token CSRF",
        )
        raise HTTPException(status_code=403, detail="Nieprawidłowy token formularza.")
    if payload != expected:
        record_security_event(
            db,
            "csrf_failed",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details="Token CSRF nie odpowiada bieżącej sesji",
        )
        raise HTTPException(status_code=403, detail="Nieprawidłowy token formularza.")


def render_template(
    request: Request, template_name: str, context: dict, status_code: int = 200
) -> HTMLResponse:
    full_context = {"request": request, **context}
    user = full_context.get("user")
    if user is not None and "csrf_token" not in full_context:
        full_context["csrf_token"] = create_auth_csrf_token(request, user)
    return templates.TemplateResponse(
        request, template_name, full_context, status_code=status_code
    )


def revoke_user_sessions(
    db: Session,
    user_id: int,
    reason: str,
    exclude_session_id: Optional[str] = None,
) -> int:
    query = db.query(UserSession).filter(
        UserSession.user_id == user_id, UserSession.revoked_at.is_(None)
    )
    if exclude_session_id:
        query = query.filter(UserSession.id != exclude_session_id)
    now = datetime.utcnow()
    sessions = query.all()
    for session in sessions:
        session.revoked_at = now
        session.revoked_reason = reason
    return len(sessions)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    cookie_val = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie_val:
        return None
    try:
        data = session_serializer.loads(cookie_val, max_age=SESSION_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None

    user_id = data.get("user_id")
    session_id = data.get("session_id")
    if not user_id or not session_id:
        return None

    session = (
        db.query(UserSession)
        .filter(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
        )
        .first()
    )
    if not session:
        return None

    now = datetime.utcnow()
    if now > session.expires_at:
        session.revoked_at = now
        session.revoked_reason = "expired"
        record_security_event(
            db,
            "session_expired",
            severity="INFO",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            details=f"Sesja {session.id[:8]} wygasła (bezwzględny limit czasu)",
        )
        return None

    if (now - session.last_seen_at).total_seconds() > SESSION_IDLE_TIMEOUT_SECONDS:
        session.revoked_at = now
        session.revoked_reason = "idle_timeout"
        record_security_event(
            db,
            "session_expired",
            severity="INFO",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            details=f"Sesja {session.id[:8]} wygasła po okresie bezczynności",
        )
        return None

    user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if not user or data.get("session_version", -1) != user.session_version:
        session.revoked_at = now
        session.revoked_reason = "session_version_mismatch"
        db.commit()
        return None

    current_ua = get_user_agent(request)
    current_ip = get_client_ip(request, TRUST_PROXY_HEADERS)

    if SESSION_BIND_UA and session.user_agent != current_ua:
        session.revoked_at = now
        session.revoked_reason = "user_agent_mismatch"
        record_security_event(
            db,
            "session_anomaly",
            severity="CRITICAL",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details=f"Zmiana User-Agent w sesji {session.id[:8]}; sesja unieważniona",
        )
        return None

    if session.ip_address != current_ip:
        if SESSION_BIND_IP:
            session.revoked_at = now
            session.revoked_reason = "ip_mismatch"
            record_security_event(
                db,
                "session_anomaly",
                severity="CRITICAL",
                request=request,
                trust_proxy_headers=TRUST_PROXY_HEADERS,
                user=user,
                details=f"Zmiana IP w sesji {session.id[:8]} ({session.ip_address} -> {current_ip}); sesja unieważniona",
            )
            return None
        old_ip = session.ip_address
        session.ip_address = current_ip
        record_security_event(
            db,
            "session_anomaly",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details=f"Zmiana IP w sesji {session.id[:8]} ({old_ip} -> {current_ip})",
        )

    if (now - session.last_seen_at).total_seconds() >= 60:
        session.last_seen_at = now
        db.commit()

    request.state.session_id = session.id
    request.state.user_id = user.id
    return user


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"}
        )
    return user


def require_admin(
    request: Request,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> User:
    if user.role != "admin":
        record_security_event(
            db,
            "access_denied",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details="Próba dostępu do zasobu administratora",
        )
        raise HTTPException(
            status_code=403, detail="Wymagane uprawnienia administratora IT."
        )
    return user


async def validate_and_save_attachment(
    request: Request,
    upload_file: UploadFile,
    ticket_id: int,
    comment_id: Optional[int],
    user: User,
    db: Session,
) -> Optional[str]:
    if not upload_file or not upload_file.filename:
        return None

    if upload_file.content_type not in ALLOWED_MIME_TYPES:
        record_security_event(
            db,
            "attachment_rejected",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details=f"Niedozwolony typ MIME: {upload_file.content_type}",
        )
        return (
            f"Niedozwolony format pliku ({upload_file.content_type}). "
            f"Dozwolone formaty: PNG, JPG, GIF, WEBP, TXT, PDF."
        )

    # Limitowany odczyt strumienia (ochrona przed wyczerpaniem pamięci RAM)
    raw_bytes = await upload_file.read(MAX_ATTACHMENT_BYTES + 1)
    file_size = len(raw_bytes)

    if file_size == 0:
        return "Przesłany plik jest pusty."

    if file_size > MAX_ATTACHMENT_BYTES:
        record_security_event(
            db,
            "attachment_rejected",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details=f"Przekroczony limit rozmiaru załącznika (>{MAX_ATTACHMENT_SIZE_MB} MB)",
        )
        return (
            f"Plik przekracza maksymalny dozwolony rozmiar "
            f"({MAX_ATTACHMENT_SIZE_MB} MB)."
        )

    if not validate_magic_bytes(raw_bytes, upload_file.content_type):
        record_security_event(
            db,
            "attachment_rejected",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details=f"Niezgodność sygnatury binarnej pliku z MIME {upload_file.content_type}",
        )
        return "Zawartość pliku nie odpowiada deklarowanemu formatowi."

    attachment = Attachment(
        ticket_id=ticket_id,
        comment_id=comment_id,
        filename=sanitize_filename(upload_file.filename),
        mime_type=upload_file.content_type,
        file_size=file_size,
        data=raw_bytes,
    )
    db.add(attachment)
    db.commit()
    return None


def _render_login_page(
    request: Request, error: Optional[str] = None, status_code: int = 200
) -> HTMLResponse:
    nonce = request.cookies.get(CSRF_COOKIE_NAME) or secrets.token_urlsafe(24)
    response = templates.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "error": error,
            "csrf_token": create_anon_csrf_token(nonce),
            "show_demo_accounts": SHOW_DEMO_ACCOUNTS,
        },
        status_code=status_code,
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=nonce,
        httponly=True,
        samesite="lax",
        secure=_should_use_secure_cookie(request),
        max_age=CSRF_MAX_AGE_SECONDS,
    )
    return response


# --- ROUTING: LOGOWANIE I SESJA ---
@app.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    if user.role in ("agent", "admin"):
        return RedirectResponse(
            url="/panel/agent", status_code=status.HTTP_303_SEE_OTHER
        )
    return RedirectResponse(
        url="/panel/employee", status_code=status.HTTP_303_SEE_OTHER
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return _render_login_page(request)


@app.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    if not verify_anon_csrf_token(request, csrf_token, db):
        return _render_login_page(
            request,
            error="Sesja formularza wygasła lub token bezpieczeństwa jest nieprawidłowy. Spróbuj ponownie.",
            status_code=403,
        )

    try:
        credentials = LoginInput(username=username, password=password)
    except ValidationError:
        return _render_login_page(
            request,
            error="Nieprawidłowy format loginu lub hasła.",
            status_code=400,
        )

    client_ip = get_client_ip(request, TRUST_PROXY_HEADERS)
    if is_login_rate_limited(
        db,
        username=credentials.username,
        ip_address=client_ip,
        window_seconds=LOGIN_RATE_LIMIT_WINDOW,
        max_attempts_per_user=LOGIN_MAX_ATTEMPTS_USER,
        max_attempts_per_ip=LOGIN_MAX_ATTEMPTS_IP,
    ):
        record_security_event(
            db,
            "login_rate_limited",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            username=credentials.username,
            details="Przekroczono limit nieudanych prób logowania",
        )
        return _render_login_page(
            request,
            error="Zbyt wiele nieudanych prób logowania. Odczekaj kilkanaście minut przed kolejną próbą.",
            status_code=429,
        )

    user = db.query(User).filter(User.username == credentials.username).first()
    if not user:
        # Stałoczasowa weryfikacja dla ochrony przed enumeracją kont
        pwd_context.verify(credentials.password, _DUMMY_BCRYPT_HASH)
        password_ok = False
    else:
        password_ok = pwd_context.verify(credentials.password, user.password_hash)

    if not user or not user.is_active or not password_ok:
        record_security_event(
            db,
            "login_failed",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user if user else None,
            username=credentials.username,
            details="Nieprawidłowe dane logowania lub zablokowane konto",
        )
        return _render_login_page(
            request,
            error="Błędna nazwa użytkownika lub hasło.",
            status_code=401,
        )

    now = datetime.utcnow()
    session_id = secrets.token_urlsafe(32)
    user_session = UserSession(
        id=session_id,
        user_id=user.id,
        ip_address=client_ip,
        user_agent=get_user_agent(request),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(seconds=SESSION_MAX_AGE_SECONDS),
    )
    db.add(user_session)
    db.commit()

    record_security_event(
        db,
        "login_success",
        severity="INFO",
        request=request,
        trust_proxy_headers=TRUST_PROXY_HEADERS,
        user=user,
        details=f"Utworzono sesję {session_id[:8]}",
    )

    token = session_serializer.dumps(
        {
            "user_id": user.id,
            "session_id": session_id,
            "session_version": user.session_version,
        }
    )
    target_url = (
        "/panel/agent" if user.role in ("agent", "admin") else "/panel/employee"
    )
    response = RedirectResponse(url=target_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=_should_use_secure_cookie(request),
        max_age=SESSION_MAX_AGE_SECONDS,
    )
    response.delete_cookie(CSRF_COOKIE_NAME)
    return response


@app.post("/logout")
def logout(
    request: Request,
    csrf_token: str = Form(""),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    verify_auth_csrf(request, csrf_token, user, db)
    session_id = getattr(request.state, "session_id", None)
    if session_id:
        session = db.get(UserSession, session_id)
        if session and session.revoked_at is None:
            session.revoked_at = datetime.utcnow()
            session.revoked_reason = "user_logout"
            db.commit()
    record_security_event(
        db,
        "logout",
        severity="INFO",
        request=request,
        trust_proxy_headers=TRUST_PROXY_HEADERS,
        user=user,
        details=f"Wylogowanie sesji {(session_id or '')[:8]}",
    )
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


# --- ROUTING: MONITORING I ZARZĄDZANIE SESJAMI UŻYTKOWNIKA ---
@app.get("/sessions", response_class=HTMLResponse)
def user_sessions_page(
    request: Request,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    active_sessions = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == user.id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
        )
        .order_by(UserSession.last_seen_at.desc())
        .all()
    )
    return render_template(
        request,
        "sessions.html",
        {
            "user": user,
            "sessions": active_sessions,
            "current_session_id": getattr(request.state, "session_id", ""),
            "notice": request.query_params.get("notice"),
        },
    )


@app.post("/sessions/{session_id}/revoke")
def revoke_own_session(
    session_id: str,
    request: Request,
    csrf_token: str = Form(""),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    verify_auth_csrf(request, csrf_token, user, db)
    target = (
        db.query(UserSession)
        .filter(UserSession.id == session_id, UserSession.user_id == user.id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Sesja nie istnieje.")
    if target.revoked_at is None:
        target.revoked_at = datetime.utcnow()
        target.revoked_reason = "revoked_by_user"
        db.commit()
        record_security_event(
            db,
            "session_revoked",
            severity="INFO",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details=f"Użytkownik unieważnił sesję {session_id[:8]}",
        )
    if session_id == getattr(request.state, "session_id", ""):
        response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response
    return RedirectResponse(
        url="/sessions?notice=" + quote("Wybrana sesja została unieważniona."),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/sessions/revoke-all")
def revoke_all_other_sessions(
    request: Request,
    csrf_token: str = Form(""),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    verify_auth_csrf(request, csrf_token, user, db)
    current_sid = getattr(request.state, "session_id", "")
    revoked_count = revoke_user_sessions(
        db, user.id, reason="revoked_other_sessions", exclude_session_id=current_sid
    )
    db.commit()
    record_security_event(
        db,
        "session_revoked",
        severity="INFO",
        request=request,
        trust_proxy_headers=TRUST_PROXY_HEADERS,
        user=user,
        details=f"Użytkownik unieważnił {revoked_count} pozostałych sesji",
    )
    return RedirectResponse(
        url="/sessions?notice="
        + quote(f"Unieważniono pozostałe aktywne sesje ({revoked_count})."),
        status_code=status.HTTP_303_SEE_OTHER,
    )


# --- ROUTING: DEDYKOWANY PANEL PRACOWNIKA ---
@app.get("/panel/employee", response_class=HTMLResponse)
def employee_panel(
    request: Request,
    error: Optional[str] = None,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if user.role != "employee":
        return RedirectResponse(
            url="/panel/agent", status_code=status.HTTP_303_SEE_OTHER
        )

    my_tickets = (
        db.query(Ticket)
        .filter(Ticket.creator_id == user.id)
        .order_by(Ticket.updated_at.desc())
        .all()
    )
    return render_template(
        request,
        "employee_panel.html",
        {
            "user": user,
            "tickets": my_tickets,
            "categories": ALLOWED_CATEGORIES,
            "priorities": ALLOWED_PRIORITIES,
            "max_size_mb": MAX_ATTACHMENT_SIZE_MB,
            "error": error,
        },
    )


@app.post("/tickets/create", response_class=HTMLResponse)
async def create_ticket(
    request: Request,
    title: str = Form(...),
    category: str = Form(...),
    priority: str = Form(...),
    description: str = Form(...),
    csrf_token: str = Form(""),
    attachment: Optional[UploadFile] = File(None),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    verify_auth_csrf(request, csrf_token, user, db)
    if user.role != "employee":
        raise HTTPException(
            status_code=403,
            detail="Tylko pracownicy mogą tworzyć zgłoszenia w tym widoku.",
        )

    try:
        validated = TicketCreateInput(
            title=title, category=category, priority=priority, description=description
        )
    except ValidationError as exc:
        err_msg = "; ".join([e["msg"] for e in exc.errors()])
        return employee_panel(
            request=request,
            error=f"Błąd walidacji formularza: {err_msg}",
            user=user,
            db=db,
        )

    new_ticket = Ticket(
        title=validated.title,
        description=validated.description,
        category=validated.category,
        priority=validated.priority,
        status="Nowy",
        creator_id=user.id,
    )
    db.add(new_ticket)
    db.commit()
    db.refresh(new_ticket)

    if attachment and attachment.filename:
        err = await validate_and_save_attachment(
            request, attachment, new_ticket.id, None, user, db
        )
        if err:
            return RedirectResponse(
                url=f"/tickets/{new_ticket.id}?error={quote(err)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )

    return RedirectResponse(
        url=f"/tickets/{new_ticket.id}", status_code=status.HTTP_303_SEE_OTHER
    )


# --- ROUTING: DEDYKOWANY PANEL AGENTA IT ---
@app.get("/panel/agent", response_class=HTMLResponse)
def agent_panel(
    request: Request,
    status_filter: Optional[str] = None,
    priority_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
    assignment_filter: Optional[str] = None,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if user.role not in ("agent", "admin"):
        return RedirectResponse(
            url="/panel/employee", status_code=status.HTTP_303_SEE_OTHER
        )

    query = db.query(Ticket)

    if status_filter and status_filter in ALLOWED_STATUSES:
        query = query.filter(Ticket.status == status_filter)
    if priority_filter and priority_filter in ALLOWED_PRIORITIES:
        query = query.filter(Ticket.priority == priority_filter)
    if category_filter and category_filter in ALLOWED_CATEGORIES:
        query = query.filter(Ticket.category == category_filter)
    if assignment_filter == "unassigned":
        query = query.filter(Ticket.assigned_agent_id.is_(None))
    elif assignment_filter == "mine":
        query = query.filter(Ticket.assigned_agent_id == user.id)

    tickets = query.order_by(Ticket.updated_at.desc()).all()

    return render_template(
        request,
        "agent_panel.html",
        {
            "user": user,
            "tickets": tickets,
            "statuses": ALLOWED_STATUSES,
            "priorities": ALLOWED_PRIORITIES,
            "categories": ALLOWED_CATEGORIES,
            "filters": {
                "status": status_filter or "",
                "priority": priority_filter or "",
                "category": category_filter or "",
                "assignment": assignment_filter or "",
            },
        },
    )


@app.post("/tickets/{ticket_id}/claim")
def claim_ticket(
    ticket_id: int,
    request: Request,
    csrf_token: str = Form(""),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    verify_auth_csrf(request, csrf_token, user, db)
    if user.role not in ("agent", "admin"):
        raise HTTPException(status_code=403, detail="Brak uprawnień Agenta IT.")

    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie istnieje.")

    ticket.assigned_agent_id = user.id
    if ticket.status == "Nowy":
        ticket.status = "W trakcie"
    db.commit()

    return RedirectResponse(
        url=f"/tickets/{ticket_id}", status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/tickets/{ticket_id}/status")
def update_ticket_status(
    ticket_id: int,
    request: Request,
    new_status: str = Form(...),
    csrf_token: str = Form(""),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    verify_auth_csrf(request, csrf_token, user, db)
    if user.role not in ("agent", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Tylko Agent IT może bezpośrednio zmieniać status sprawy.",
        )

    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie istnieje.")

    try:
        validated = StatusUpdateInput(status=new_status)
    except ValidationError:
        raise HTTPException(status_code=400, detail="Nieprawidłowy status zgłoszenia.")

    ticket.status = validated.status
    db.commit()

    return RedirectResponse(
        url=f"/tickets/{ticket_id}", status_code=status.HTTP_303_SEE_OTHER
    )


# --- ROUTING: SZCZEGÓŁY ZGŁOSZENIA, WĄTEK KOMENTARZY I ZAŁĄCZNIKI ---
@app.get("/tickets/{ticket_id}", response_class=HTMLResponse)
def ticket_detail(
    ticket_id: int,
    request: Request,
    error: Optional[str] = None,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(
            status_code=404, detail="Zgłoszenie nie zostało znalezione."
        )

    if user.role == "employee" and ticket.creator_id != user.id:
        record_security_event(
            db,
            "access_denied",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details=f"Próba odczytu cudzego zgłoszenia #{ticket_id}",
        )
        raise HTTPException(
            status_code=403, detail="Brak dostępu do cudzego zgłoszenia."
        )

    return render_template(
        request,
        "ticket_detail.html",
        {
            "user": user,
            "ticket": ticket,
            "statuses": ALLOWED_STATUSES,
            "max_size_mb": MAX_ATTACHMENT_SIZE_MB,
            "error": error,
        },
    )


@app.post("/tickets/{ticket_id}/comments")
async def add_comment(
    ticket_id: int,
    request: Request,
    content: str = Form(...),
    new_status: Optional[str] = Form(None),
    csrf_token: str = Form(""),
    attachment: Optional[UploadFile] = File(None),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    verify_auth_csrf(request, csrf_token, user, db)
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie istnieje.")

    if user.role == "employee" and ticket.creator_id != user.id:
        raise HTTPException(status_code=403, detail="Brak dostępu do tego zgłoszenia.")

    if ticket.status == "Zamknięty" and user.role not in ("agent", "admin"):
        return RedirectResponse(
            url=f"/tickets/{ticket_id}?error="
            + quote("Zgłoszenie jest zamknięte. Nie można dodawać nowych komentarzy."),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    status_val = (
        new_status if (new_status and new_status in ALLOWED_STATUSES) else None
    )

    try:
        validated = CommentCreateInput(content=content, new_status=status_val)
    except ValidationError:
        return RedirectResponse(
            url=f"/tickets/{ticket_id}?error="
            + quote("Treść komentarza jest nieprawidłowa."),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    comment = Comment(ticket_id=ticket.id, author_id=user.id, content=validated.content)
    db.add(comment)

    if user.role in ("agent", "admin"):
        if not ticket.assigned_agent_id:
            ticket.assigned_agent_id = user.id
        if validated.new_status:
            ticket.status = validated.new_status
        elif ticket.status == "Nowy":
            ticket.status = "W trakcie"
    else:
        if ticket.status == "Rozwiązany":
            ticket.status = "W trakcie"

    db.commit()
    db.refresh(comment)

    if attachment and attachment.filename:
        err = await validate_and_save_attachment(
            request, attachment, ticket.id, comment.id, user, db
        )
        if err:
            return RedirectResponse(
                url=f"/tickets/{ticket_id}?error={quote(err)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )

    return RedirectResponse(
        url=f"/tickets/{ticket_id}", status_code=status.HTTP_303_SEE_OTHER
    )


@app.get("/attachments/{attachment_id}")
def get_attachment(
    attachment_id: int,
    request: Request,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    attachment = db.query(Attachment).filter(Attachment.id == attachment_id).first()
    if not attachment:
        raise HTTPException(status_code=404, detail="Załącznik nie istnieje.")

    ticket = attachment.ticket
    if user.role == "employee" and ticket.creator_id != user.id:
        record_security_event(
            db,
            "access_denied",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details=f"Próba pobrania cudzego załącznika #{attachment_id}",
        )
        raise HTTPException(
            status_code=403, detail="Brak uprawnień do pobrania tego załącznika."
        )

    safe_name = sanitize_filename(attachment.filename)
    disposition = (
        "inline"
        if attachment.mime_type in {"image/png", "image/jpeg", "image/gif", "image/webp"}
        else "attachment"
    )
    headers = {
        "Content-Disposition": f'{disposition}; filename="{safe_name}"',
        "X-Content-Type-Options": "nosniff",
    }
    return Response(
        content=attachment.data, media_type=attachment.mime_type, headers=headers
    )


# --- ROUTING: ZARZĄDZANIE UŻYTKOWNIKAMI I AUDYT BEZPIECZEŃSTWA (ADMIN) ---
def render_user_form(
    request, user, db, editing=None, values=None, error=None, status_code=200
):
    return render_template(
        request,
        "user_form.html",
        {
            "user": user,
            "editing": editing,
            "values": values if values is not None else editing,
            "roles": USER_ROLES,
            "error": error,
        },
        status_code=status_code,
    )


@app.get("/admin/users", response_class=HTMLResponse)
def users_panel(
    request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    return render_template(
        request,
        "users.html",
        {
            "user": user,
            "roles": USER_ROLES,
            "users": db.query(User).order_by(User.username).all(),
            "saved": request.query_params.get("saved") == "1",
        },
    )


@app.get("/admin/users/new", response_class=HTMLResponse)
def new_user_form(
    request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    return render_user_form(
        request, user, db, values={"role": "employee", "is_active": True}
    )


@app.get("/admin/users/{user_id}/edit", response_class=HTMLResponse)
def edit_user_form(
    user_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    editing = db.get(User, user_id)
    if not editing:
        raise HTTPException(status_code=404, detail="Użytkownik nie istnieje.")
    return render_user_form(request, user, db, editing=editing)


def save_managed_user(
    request,
    admin,
    db,
    username,
    full_name,
    role,
    is_active,
    password,
    csrf_token,
    editing=None,
):
    verify_auth_csrf(request, csrf_token, admin, db)
    values = {
        "username": username,
        "full_name": full_name,
        "role": role,
        "is_active": is_active,
    }

    def error_response(message, code=400):
        return render_user_form(request, admin, db, editing, values, message, code)

    try:
        data = UserInput(**values, password=password)
    except ValidationError:
        return error_response(
            "Sprawdź dane: login 2–50 znaków (litery bez polskich znaków, cyfry, kropka, "
            "myślnik, podkreślenie), imię i nazwisko 2–100 znaków, poprawna rola. "
            "Hasło musi mieć co najmniej 8 znaków i maksymalnie 72 bajty UTF-8."
        )
    if not editing and not data.password:
        return error_response("Podaj hasło dla nowego użytkownika.")
    if (
        editing
        and editing.id == admin.id
        and (data.role != "admin" or not data.is_active)
    ):
        return error_response(
            "Nie możesz zablokować własnego konta ani odebrać sobie roli administratora."
        )

    duplicate = db.query(User).filter(
        func.lower(User.username) == data.username.lower()
    )
    if editing:
        duplicate = duplicate.filter(User.id != editing.id)
    if duplicate.first():
        return error_response("Użytkownik o takim loginie już istnieje.", 409)

    target = editing or User()
    should_revoke_sessions = bool(
        editing
        and (
            data.password
            or target.role != data.role
            or target.is_active != data.is_active
        )
    )
    if should_revoke_sessions:
        target.session_version += 1
    target.username = data.username
    target.full_name = data.full_name
    target.role = data.role
    target.is_active = data.is_active
    if data.password:
        target.password_hash = pwd_context.hash(data.password)
    db.add(target)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return error_response("Użytkownik o takim loginie już istnieje.", 409)

    if should_revoke_sessions:
        revoke_user_sessions(db, target.id, reason="account_updated")
        db.commit()

    record_security_event(
        db,
        "user_updated" if editing else "user_created",
        severity="INFO",
        request=request,
        trust_proxy_headers=TRUST_PROXY_HEADERS,
        user=admin,
        details=f"Konto {target.username} (rola={target.role}, aktywne={target.is_active})",
    )
    return RedirectResponse("/admin/users?saved=1", status_code=303)


@app.post("/admin/users/new", response_class=HTMLResponse)
def create_managed_user(
    request: Request,
    username: str = Form(""),
    full_name: str = Form(""),
    role: str = Form("employee"),
    is_active: bool = Form(False),
    password: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return save_managed_user(
        request, user, db, username, full_name, role, is_active, password, csrf_token
    )


@app.post("/admin/users/{user_id}/edit", response_class=HTMLResponse)
def update_managed_user(
    user_id: int,
    request: Request,
    username: str = Form(""),
    full_name: str = Form(""),
    role: str = Form("employee"),
    is_active: bool = Form(False),
    password: str = Form(""),
    csrf_token: str = Form(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    editing = db.get(User, user_id)
    if not editing:
        raise HTTPException(status_code=404, detail="Użytkownik nie istnieje.")
    return save_managed_user(
        request,
        user,
        db,
        username,
        full_name,
        role,
        is_active,
        password,
        csrf_token,
        editing,
    )


@app.get("/admin/security", response_class=HTMLResponse)
def admin_security_panel(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    active_sessions = (
        db.query(UserSession)
        .filter(UserSession.revoked_at.is_(None), UserSession.expires_at > now)
        .order_by(UserSession.last_seen_at.desc())
        .all()
    )
    recent_events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.created_at.desc())
        .limit(100)
        .all()
    )
    return render_template(
        request,
        "admin_security.html",
        {
            "user": user,
            "sessions": active_sessions,
            "events": recent_events,
            "current_session_id": getattr(request.state, "session_id", ""),
            "notice": request.query_params.get("notice"),
        },
    )


@app.post("/admin/sessions/{session_id}/revoke")
def admin_revoke_session(
    session_id: str,
    request: Request,
    csrf_token: str = Form(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    verify_auth_csrf(request, csrf_token, user, db)
    target = db.get(UserSession, session_id)
    if not target:
        raise HTTPException(status_code=404, detail="Sesja nie istnieje.")
    if target.revoked_at is None:
        target.revoked_at = datetime.utcnow()
        target.revoked_reason = "revoked_by_admin"
        db.commit()
        record_security_event(
            db,
            "session_revoked",
            severity="WARNING",
            request=request,
            trust_proxy_headers=TRUST_PROXY_HEADERS,
            user=user,
            details=f"Administrator unieważnił sesję {session_id[:8]} użytkownika {target.user.username}",
        )
    if session_id == getattr(request.state, "session_id", ""):
        response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response
    return RedirectResponse(
        url="/admin/security?notice=" + quote("Sesja została unieważniona."),
        status_code=status.HTTP_303_SEE_OTHER,
    )
