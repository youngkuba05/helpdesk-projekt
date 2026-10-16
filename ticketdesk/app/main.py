import os
from typing import Optional
from fastapi import (
    FastAPI, Request, Depends, Form, UploadFile, File, HTTPException, status
)
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import inspect, text, func
from sqlalchemy.exc import IntegrityError
from itsdangerous import URLSafeSerializer, BadSignature
from passlib.context import CryptContext
from pydantic import ValidationError

from .database import engine, SessionLocal, get_db, Base
from .models import User, Ticket, Comment, Attachment
from .schemas import (
    LoginInput, TicketCreateInput, CommentCreateInput, StatusUpdateInput,
    ALLOWED_CATEGORIES, ALLOWED_PRIORITIES, ALLOWED_STATUSES, UserInput, USER_ROLES
)

app = FastAPI(
    title="TicketDesk - IT Service Desk (DEV)",
    description="Wewnętrzny system obsługi zgłoszeń i komunikacji serwisowej IT"
)

# Montowanie plików statycznych i szablonów Jinja2 (SSR)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Konfiguracja bezstanowych ciasteczek sesyjnych i hashowania
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-ticketdesk-stateless-cookie-signing")
SESSION_COOKIE_NAME = "ticketdesk_session"
serializer = URLSafeSerializer(SECRET_KEY, salt="session-cookie")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Restrykcje załączników (walidacja rozmiaru i formatu)
MAX_ATTACHMENT_SIZE_MB = int(os.getenv("MAX_ATTACHMENT_SIZE_MB", "5"))
MAX_ATTACHMENT_BYTES = MAX_ATTACHMENT_SIZE_MB * 1024 * 1024
ALLOWED_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "text/plain",
    "application/pdf"
}


# --- INICJALIZACJA BAZY I DANYCH TESTOWYCH W ŚRODOWISKU DEV ---
@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)
    # Uzupełnienie istniejących instalacji bez usuwania danych.
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    with engine.begin() as connection:
        if "is_active" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE"))
        if "session_version" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0"))
        # Jednorazowa migracja wbudowanego konta administratora.
        if "is_active" not in columns:
            connection.execute(text(
                "UPDATE users SET role = 'admin' WHERE username = 'admin.helpdesk' AND role = 'agent'"
            ))
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            users = [
                User(
                    username="jan.kowalski",
                    full_name="Jan Kowalski (Dział Finansów)",
                    password_hash=pwd_context.hash("pracownik123"),
                    role="employee"
                ),
                User(
                    username="anna.nowak",
                    full_name="Anna Nowak (Dział HR)",
                    password_hash=pwd_context.hash("pracownik123"),
                    role="employee"
                ),
                User(
                    username="agent.it",
                    full_name="Jakub Brzostowski (Wsparcie IT)",
                    password_hash=pwd_context.hash("agent123"),
                    role="agent"
                ),
                User(
                    username="admin.helpdesk",
                    full_name="Stanisław Rajm (Administrator IT)",
                    password_hash=pwd_context.hash("agent123"),
                    role="admin"
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
                assigned_agent_id=agent.id
            )
            db.add(sample_ticket)
            db.commit()
            db.refresh(sample_ticket)

            sample_comment = Comment(
                ticket_id=sample_ticket.id,
                author_id=agent.id,
                content="Cześć Janie, zweryfikowałem logi bramy VPN. Załącz proszę zrzut ekranu z komunikatem błędu z klienta OpenVPN."
            )
            db.add(sample_comment)
            db.commit()
    finally:
        db.close()


# --- FUNKCJE POMOCNICZE SESJI I AUTORYZACJI ---
def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    cookie_val = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie_val:
        return None
    try:
        data = serializer.loads(cookie_val)
        user_id = data.get("user_id")
        if not user_id:
            return None
        user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
        if user and data.get("session_version", 0) == user.session_version:
            return user
        return None
    except BadSignature:
        return None


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"}
        )
    return user


async def validate_and_save_attachment(
    upload_file: UploadFile,
    ticket_id: int,
    comment_id: Optional[int],
    db: Session
) -> Optional[str]:
    if not upload_file or not upload_file.filename:
        return None

    if upload_file.content_type not in ALLOWED_MIME_TYPES:
        return (
            f"Niedozwolony format pliku ({upload_file.content_type}). "
            f"Dozwolone formaty: PNG, JPG, GIF, WEBP, TXT, PDF."
        )

    raw_bytes = await upload_file.read()
    file_size = len(raw_bytes)

    if file_size == 0:
        return "Przesłany plik jest pusty."

    if file_size > MAX_ATTACHMENT_BYTES:
        return (
            f"Plik przekracza maksymalny dozwolony rozmiar "
            f"({MAX_ATTACHMENT_SIZE_MB} MB)."
        )

    attachment = Attachment(
        ticket_id=ticket_id,
        comment_id=comment_id,
        filename=os.path.basename(upload_file.filename),
        mime_type=upload_file.content_type,
        file_size=file_size,
        data=raw_bytes
    )
    db.add(attachment)
    db.commit()
    return None


# --- ROUTING: LOGOWANIE I SESJA ---
@app.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    if user.role in ("agent", "admin"):
        return RedirectResponse(url="/panel/agent", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/panel/employee", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        credentials = LoginInput(username=username, password=password)
    except ValidationError:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Nieprawidłowy format loginu lub hasła."},
            status_code=400
        )

    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not user.is_active or not pwd_context.verify(credentials.password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Błędna nazwa użytkownika lub hasło."},
            status_code=401
        )

    # Wersja sesji pozwala unieważnić ciasteczka po zmianie hasła lub uprawnień.
    token = serializer.dumps({"user_id": user.id, "session_version": user.session_version})
    target_url = "/panel/agent" if user.role in ("agent", "admin") else "/panel/employee"
    response = RedirectResponse(url=target_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=86400
    )
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


# --- ROUTING: DEDYKOWANY PANEL PRACOWNIKA ---
@app.get("/panel/employee", response_class=HTMLResponse)
def employee_panel(
    request: Request,
    error: Optional[str] = None,
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    if user.role != "employee":
        return RedirectResponse(url="/panel/agent", status_code=status.HTTP_303_SEE_OTHER)

    my_tickets = (
        db.query(Ticket)
        .filter(Ticket.creator_id == user.id)
        .order_by(Ticket.updated_at.desc())
        .all()
    )
    return templates.TemplateResponse(
        "employee_panel.html",
        {
            "request": request,
            "user": user,
            "tickets": my_tickets,
            "categories": ALLOWED_CATEGORIES,
            "priorities": ALLOWED_PRIORITIES,
            "max_size_mb": MAX_ATTACHMENT_SIZE_MB,
            "error": error
        }
    )


@app.post("/tickets/create", response_class=HTMLResponse)
async def create_ticket(
    request: Request,
    title: str = Form(...),
    category: str = Form(...),
    priority: str = Form(...),
    description: str = Form(...),
    attachment: Optional[UploadFile] = File(None),
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    if user.role != "employee":
        raise HTTPException(status_code=403, detail="Tylko pracownicy mogą tworzyć zgłoszenia w tym widoku.")

    try:
        validated = TicketCreateInput(
            title=title,
            category=category,
            priority=priority,
            description=description
        )
    except ValidationError as exc:
        err_msg = "; ".join([e["msg"] for e in exc.errors()])
        return employee_panel(request=request, error=f"Błąd walidacji formularza: {err_msg}", user=user, db=db)

    new_ticket = Ticket(
        title=validated.title,
        description=validated.description,
        category=validated.category,
        priority=validated.priority,
        status="Nowy",
        creator_id=user.id
    )
    db.add(new_ticket)
    db.commit()
    db.refresh(new_ticket)

    if attachment and attachment.filename:
        err = await validate_and_save_attachment(attachment, new_ticket.id, None, db)
        if err:
            return RedirectResponse(
                url=f"/tickets/{new_ticket.id}?error={err}",
                status_code=status.HTTP_303_SEE_OTHER
            )

    return RedirectResponse(
        url=f"/tickets/{new_ticket.id}",
        status_code=status.HTTP_303_SEE_OTHER
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
    db: Session = Depends(get_db)
):
    if user.role not in ("agent", "admin"):
        return RedirectResponse(url="/panel/employee", status_code=status.HTTP_303_SEE_OTHER)

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

    return templates.TemplateResponse(
        "agent_panel.html",
        {
            "request": request,
            "user": user,
            "tickets": tickets,
            "statuses": ALLOWED_STATUSES,
            "priorities": ALLOWED_PRIORITIES,
            "categories": ALLOWED_CATEGORIES,
            "filters": {
                "status": status_filter or "",
                "priority": priority_filter or "",
                "category": category_filter or "",
                "assignment": assignment_filter or ""
            }
        }
    )


@app.post("/tickets/{ticket_id}/claim")
def claim_ticket(
    ticket_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
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
        url=f"/tickets/{ticket_id}",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/tickets/{ticket_id}/status")
def update_ticket_status(
    ticket_id: int,
    new_status: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    if user.role not in ("agent", "admin"):
        raise HTTPException(status_code=403, detail="Tylko Agent IT może bezpośrednio zmieniać status sprawy.")

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
        url=f"/tickets/{ticket_id}",
        status_code=status.HTTP_303_SEE_OTHER
    )


# --- ROUTING: SZCZEGÓŁY ZGŁOSZENIA, WĄTEK KOMENTARZY I ZAŁĄCZNIKI ---
@app.get("/tickets/{ticket_id}", response_class=HTMLResponse)
def ticket_detail(
    ticket_id: int,
    request: Request,
    error: Optional[str] = None,
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie zostało znalezione.")

    # Kontrola dostępu: pracownik widzi wyłącznie swoje zgłoszenia, Agent IT widzi wszystkie
    if user.role == "employee" and ticket.creator_id != user.id:
        raise HTTPException(status_code=403, detail="Brak dostępu do cudzego zgłoszenia.")

    return templates.TemplateResponse(
        "ticket_detail.html",
        {
            "request": request,
            "user": user,
            "ticket": ticket,
            "statuses": ALLOWED_STATUSES,
            "max_size_mb": MAX_ATTACHMENT_SIZE_MB,
            "error": error
        }
    )


@app.post("/tickets/{ticket_id}/comments")
async def add_comment(
    ticket_id: int,
    content: str = Form(...),
    new_status: Optional[str] = Form(None),
    attachment: Optional[UploadFile] = File(None),
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie istnieje.")

    if user.role == "employee" and ticket.creator_id != user.id:
        raise HTTPException(status_code=403, detail="Brak dostępu do tego zgłoszenia.")

    if ticket.status == "Zamknięty" and user.role not in ("agent", "admin"):
        return RedirectResponse(
            url=f"/tickets/{ticket_id}?error=Zgłoszenie jest zamknięte. Nie można dodawać nowych komentarzy.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    status_val = new_status if (new_status and new_status in ALLOWED_STATUSES) else None

    try:
        validated = CommentCreateInput(content=content, new_status=status_val)
    except ValidationError:
        return RedirectResponse(
            url=f"/tickets/{ticket_id}?error=Treść komentarza jest nieprawidłowa.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    comment = Comment(
        ticket_id=ticket.id,
        author_id=user.id,
        content=validated.content
    )
    db.add(comment)

    # Dynamiczna zmiana statusu sprawy przy odpowiedzi
    if user.role in ("agent", "admin"):
        if not ticket.assigned_agent_id:
            ticket.assigned_agent_id = user.id
        if validated.new_status:
            ticket.status = validated.new_status
        elif ticket.status == "Nowy":
            ticket.status = "W trakcie"
    else:
        # Gdy pracownik odpowiada w rozwiązanym zgłoszeniu, wznawiamy wątek
        if ticket.status == "Rozwiązany":
            ticket.status = "W trakcie"

    db.commit()
    db.refresh(comment)

    if attachment and attachment.filename:
        err = await validate_and_save_attachment(attachment, ticket.id, comment.id, db)
        if err:
            return RedirectResponse(
                url=f"/tickets/{ticket_id}?error={err}",
                status_code=status.HTTP_303_SEE_OTHER
            )

    return RedirectResponse(
        url=f"/tickets/{ticket_id}",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.get("/attachments/{attachment_id}")
def get_attachment(
    attachment_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db)
):
    attachment = db.query(Attachment).filter(Attachment.id == attachment_id).first()
    if not attachment:
        raise HTTPException(status_code=404, detail="Załącznik nie istnieje.")

    ticket = attachment.ticket
    if user.role == "employee" and ticket.creator_id != user.id:
        raise HTTPException(status_code=403, detail="Brak uprawnień do pobrania tego załącznika.")

    disposition = "inline" if attachment.mime_type.startswith("image/") else "attachment"
    headers = {
        "Content-Disposition": f'{disposition}; filename="{attachment.filename}"'
    }
    return Response(content=attachment.data, media_type=attachment.mime_type, headers=headers)


# --- ROUTING: ZARZĄDZANIE UŻYTKOWNIKAMI PRZEZ ADMINISTRATORA IT ---
def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Wymagane uprawnienia administratora IT.")
    return user


def admin_csrf_token(user: User) -> str:
    return serializer.dumps({"purpose": "manage-users", "user_id": user.id,
                             "session_version": user.session_version})


def verify_admin_csrf(token: str, user: User):
    try:
        payload = serializer.loads(token)
    except BadSignature:
        raise HTTPException(status_code=403, detail="Nieprawidłowy token formularza.")
    if payload != {"purpose": "manage-users", "user_id": user.id,
                   "session_version": user.session_version}:
        raise HTTPException(status_code=403, detail="Nieprawidłowy token formularza.")


def render_user_form(request, user, db, editing=None, values=None, error=None, status_code=200):
    return templates.TemplateResponse("user_form.html", {
        "request": request, "user": user, "editing": editing,
        "values": values if values is not None else editing,
        "roles": USER_ROLES, "csrf_token": admin_csrf_token(user), "error": error,
    }, status_code=status_code)


@app.get("/admin/users", response_class=HTMLResponse)
def users_panel(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    return templates.TemplateResponse("users.html", {
        "request": request, "user": user, "roles": USER_ROLES,
        "users": db.query(User).order_by(User.username).all(),
        "saved": request.query_params.get("saved") == "1",
    })


@app.get("/admin/users/new", response_class=HTMLResponse)
def new_user_form(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    return render_user_form(request, user, db, values={"role": "employee", "is_active": True})


@app.get("/admin/users/{user_id}/edit", response_class=HTMLResponse)
def edit_user_form(user_id: int, request: Request, user: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    editing = db.get(User, user_id)
    if not editing:
        raise HTTPException(status_code=404, detail="Użytkownik nie istnieje.")
    return render_user_form(request, user, db, editing=editing)


def save_managed_user(request, admin, db, username, full_name, role, is_active, password,
                      csrf_token, editing=None):
    verify_admin_csrf(csrf_token, admin)
    values = {"username": username, "full_name": full_name, "role": role, "is_active": is_active}

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
    if editing and editing.id == admin.id and (data.role != "admin" or not data.is_active):
        return error_response("Nie możesz zablokować własnego konta ani odebrać sobie roli administratora.")

    duplicate = db.query(User).filter(func.lower(User.username) == data.username.lower())
    if editing:
        duplicate = duplicate.filter(User.id != editing.id)
    if duplicate.first():
        return error_response("Użytkownik o takim loginie już istnieje.", 409)

    target = editing or User()
    if editing and (data.password or target.role != data.role or target.is_active != data.is_active):
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
    return RedirectResponse("/admin/users?saved=1", status_code=303)


@app.post("/admin/users/new", response_class=HTMLResponse)
def create_managed_user(
    request: Request, username: str = Form(""), full_name: str = Form(""),
    role: str = Form("employee"), is_active: bool = Form(False), password: str = Form(""),
    csrf_token: str = Form(""), user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    return save_managed_user(request, user, db, username, full_name, role, is_active, password, csrf_token)


@app.post("/admin/users/{user_id}/edit", response_class=HTMLResponse)
def update_managed_user(
    user_id: int, request: Request, username: str = Form(""), full_name: str = Form(""),
    role: str = Form("employee"), is_active: bool = Form(False), password: str = Form(""),
    csrf_token: str = Form(""), user: User = Depends(require_admin), db: Session = Depends(get_db)
):
    editing = db.get(User, user_id)
    if not editing:
        raise HTTPException(status_code=404, detail="Użytkownik nie istnieje.")
    return save_managed_user(request, user, db, username, full_name, role, is_active, password,
                             csrf_token, editing)
