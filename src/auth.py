
import hashlib
import re
import secrets


class RegistrationService:
    """Учебный прототип регистрации пользователей."""

    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.sent_emails = []

    def register(self, email, password, password_confirmation):
        email = email.strip().lower()

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError("Некорректный email")

        if len(password) < 8:
            raise ValueError("Пароль должен содержать не менее 8 символов")

        if password != password_confirmation:
            raise ValueError("Пароли не совпадают")

        if email in self.users:
            raise ValueError("Этот email уже зарегистрирован")

        salt = secrets.token_bytes(16)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            200_000
        )

        self.users[email] = {
            "email": email,
            "salt": salt.hex(),
            "password_hash": password_hash.hex()
        }

        session_token = secrets.token_urlsafe(32)
        self.sessions[session_token] = email

        # Учебная имитация отправки письма.
        self.sent_emails.append({
            "to": email,
            "subject": "Добро пожаловать в Fitness App!"
        })

        return {
            "email": email,
            "session_token": session_token
        }
