from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator

ALLOWED_CATEGORIES = ("Sprzęt", "Oprogramowanie", "Sieć i VPN", "Dostępy i Konta", "Inne")
ALLOWED_PRIORITIES = ("Niski", "Średni", "Wysoki", "Krytyczny")
ALLOWED_STATUSES = ("Nowy", "W trakcie", "Rozwiązany", "Zamknięty")


class LoginInput(BaseModel):
    username: str = Field(..., min_length=2, max_length=50)
    password: str = Field(..., min_length=3, max_length=128)


class TicketCreateInput(BaseModel):
    title: str = Field(..., min_length=5, max_length=200)
    description: str = Field(..., min_length=10, max_length=5000)
    category: Literal["Sprzęt", "Oprogramowanie", "Sieć i VPN", "Dostępy i Konta", "Inne"]
    priority: Literal["Niski", "Średni", "Wysoki", "Krytyczny"]

    @field_validator("title", "description")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Pole nie może składać się wyłącznie z białych znaków.")
        return cleaned


class CommentCreateInput(BaseModel):
    content: str = Field(..., min_length=1, max_length=3000)
    new_status: Optional[Literal["Nowy", "W trakcie", "Rozwiązany", "Zamknięty"]] = None

    @field_validator("content")
    @classmethod
    def strip_content(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Treść wiadomości nie może być pusta.")
        return cleaned


class StatusUpdateInput(BaseModel):
    status: Literal["Nowy", "W trakcie", "Rozwiązany", "Zamknięty"]


USER_ROLES = {"employee": "Pracownik", "agent": "Agent IT", "admin": "Administrator IT"}


class UserInput(BaseModel):
    username: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    full_name: str = Field(..., min_length=2, max_length=100)
    role: Literal["employee", "agent", "admin"]
    is_active: bool = True
    password: str = ""

    @field_validator("username", "full_name", mode="before")
    @classmethod
    def trim_identity(cls, value: str) -> str:
        return value.strip()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if value and (len(value) < 8 or len(value.encode("utf-8")) > 72):
            raise ValueError("Hasło musi mieć co najmniej 8 znaków i maksymalnie 72 bajty UTF-8.")
        return value
