
import pytest

from src.auth import RegistrationService


@pytest.fixture
def service():
    return RegistrationService()


def test_successful_registration(service):
    result = service.register(
        "user@example.com",
        "password123",
        "password123"
    )

    assert result["email"] == "user@example.com"
    assert result["session_token"]


def test_invalid_email(service):
    with pytest.raises(ValueError, match="email"):
        service.register(
            "invalid-email",
            "password123",
            "password123"
        )


def test_short_password(service):
    with pytest.raises(ValueError, match="8 символов"):
        service.register(
            "user@example.com",
            "123",
            "123"
        )


def test_password_mismatch(service):
    with pytest.raises(ValueError, match="не совпадают"):
        service.register(
            "user@example.com",
            "password123",
            "different123"
        )


def test_duplicate_email(service):
    service.register(
        "user@example.com",
        "password123",
        "password123"
    )

    with pytest.raises(ValueError, match="уже зарегистрирован"):
        service.register(
            "user@example.com",
            "password456",
            "password456"
        )


def test_email_is_normalized(service):
    result = service.register(
        "USER@EXAMPLE.COM",
        "password123",
        "password123"
    )

    assert result["email"] == "user@example.com"


def test_password_is_hashed(service):
    service.register(
        "user@example.com",
        "password123",
        "password123"
    )

    saved = service.users["user@example.com"]

    assert saved["password_hash"] != "password123"
    assert saved["salt"]


def test_automatic_login(service):
    result = service.register(
        "user@example.com",
        "password123",
        "password123"
    )

    token = result["session_token"]

    assert service.sessions[token] == "user@example.com"


def test_welcome_email_simulation(service):
    service.register(
        "user@example.com",
        "password123",
        "password123"
    )

    assert len(service.sent_emails) == 1
    assert service.sent_emails[0]["to"] == "user@example.com"
