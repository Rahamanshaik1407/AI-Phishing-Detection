"""
Authentication tests for Phase 2.

Uses a temporary SQLite database to avoid affecting production data.
Covers: registration, login, JWT, /me, password change, inactive user,
invalid tokens, user isolation at the database/model level.
"""

import os
import time
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# -------------------------------------------------------------------
# Test environment setup — MUST be done before importing app modules
# -------------------------------------------------------------------

TEST_DB_PATH = Path("./test_phishguard_auth.db")

if TEST_DB_PATH.exists():
    TEST_DB_PATH.unlink()

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"

# Import after setting env var
from app.main import app  # noqa: E402
from app import models, database, auth as auth_utils, schemas  # noqa: E402

client = TestClient(app)

# -------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------

@pytest.fixture(scope="function", autouse=True)
def reset_database():
    """Drop and recreate all tables for each test to guarantee isolation."""
    models.Base.metadata.drop_all(bind=database.engine)
    models.Base.metadata.create_all(bind=database.engine)
    yield


# -------------------------------------------------------------------
# Test data
# -------------------------------------------------------------------

USER_PAYLOAD = {
    "username": "testuser",
    "email": "test@example.com",
    "password": "StrongPass123!",
}


# -------------------------------------------------------------------
# Helper: register + login, return token
# -------------------------------------------------------------------

def register_and_login() -> str:
    """Register the default test user and return a valid JWT token."""
    client.post("/api/v1/auth/register", json=USER_PAYLOAD)
    login = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": USER_PAYLOAD["email"],
              "password": USER_PAYLOAD["password"]},
    )
    return login.json()["access_token"]


# ===================================================================
# 1. Registration
# ===================================================================

def test_successful_registration():
    resp = client.post("/api/v1/auth/register", json=USER_PAYLOAD)
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    user = data["user"]
    assert user["email"] == USER_PAYLOAD["email"]
    assert user["username"] == USER_PAYLOAD["username"]
    assert "password" not in user
    assert "password_hash" not in user


def test_duplicate_registration():
    client.post("/api/v1/auth/register", json=USER_PAYLOAD)
    dup = client.post("/api/v1/auth/register", json=USER_PAYLOAD)
    assert dup.status_code == 400
    assert dup.json()["detail"] == "Username or email already registered."


def test_password_is_hashed_not_plaintext():
    """The password stored in the DB must be an Argon2id hash, not plaintext."""
    client.post("/api/v1/auth/register", json=USER_PAYLOAD)
    db = database.SessionLocal()
    try:
        db_user = db.query(models.User).filter(
            models.User.email == USER_PAYLOAD["email"]
        ).first()
        assert db_user is not None
        # Must NOT be the plaintext password
        assert db_user.password_hash != USER_PAYLOAD["password"]
        # Must start with Argon2id identifier
        assert db_user.password_hash.startswith("$argon2id$")
        # Must verify correctly
        assert auth_utils.verify_password(
            USER_PAYLOAD["password"], db_user.password_hash
        )
    finally:
        db.close()


# ===================================================================
# 2. Login
# ===================================================================

def test_successful_login():
    client.post("/api/v1/auth/register", json=USER_PAYLOAD)
    resp = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": USER_PAYLOAD["email"],
              "password": USER_PAYLOAD["password"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["email"] == USER_PAYLOAD["email"]


def test_login_invalid_password():
    client.post("/api/v1/auth/register", json=USER_PAYLOAD)
    resp = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": USER_PAYLOAD["email"],
              "password": "WrongPass!99"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials."


def test_login_nonexistent_user():
    resp = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": "ghost@nowhere.com", "password": "any"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials."


# ===================================================================
# 3. JWT validation
# ===================================================================

def test_jwt_token_generation():
    """create_access_token produces a decodable token with correct sub claim."""
    token = auth_utils.create_access_token(data={"sub": "42"})
    payload = auth_utils.decode_access_token(token)
    assert payload["sub"] == "42"
    assert "exp" in payload
    assert "iat" in payload


# ===================================================================
# 4. /me endpoint
# ===================================================================

def test_me_without_token():
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_me_with_invalid_token():
    headers = {"Authorization": "Bearer this.is.not.a.valid.jwt"}
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 401


def test_me_with_valid_token():
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == USER_PAYLOAD["email"]
    assert data["username"] == USER_PAYLOAD["username"]
    assert "password" not in data
    assert "password_hash" not in data


# ===================================================================
# 5. Password change
# ===================================================================

def test_change_password_success():
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}
    new_pw = "BrandNewPass789!"
    resp = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": USER_PAYLOAD["password"],
              "new_password": new_pw},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["detail"] == "Password changed successfully."


def test_change_password_incorrect_current():
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "WrongCurrent!", "new_password": "NewPass123!"},
        headers=headers,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Current password is incorrect."


def test_new_password_works_after_change():
    """After changing a password, the new password must work for login."""
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}
    new_pw = "ChangedPass456!"
    client.post(
        "/api/v1/auth/change-password",
        json={"current_password": USER_PAYLOAD["password"],
              "new_password": new_pw},
        headers=headers,
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": USER_PAYLOAD["email"], "password": new_pw},
    )
    assert login.status_code == 200
    assert "access_token" in login.json()


# ===================================================================
# 6. Inactive / deactivated user
# ===================================================================

def test_inactive_user_cannot_login():
    """A user with is_active=False must be rejected at login."""
    client.post("/api/v1/auth/register", json=USER_PAYLOAD)
    # Deactivate in database directly
    db = database.SessionLocal()
    try:
        u = db.query(models.User).filter(
            models.User.email == USER_PAYLOAD["email"]
        ).first()
        u.is_active = False
        db.commit()
    finally:
        db.close()
    resp = client.post(
        "/api/v1/auth/login",
        json={"email_or_username": USER_PAYLOAD["email"],
              "password": USER_PAYLOAD["password"]},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "User account is deactivated."


def test_inactive_user_cannot_access_me():
    """A token minted before deactivation must be rejected on /me."""
    token = register_and_login()
    # Deactivate
    db = database.SessionLocal()
    try:
        u = db.query(models.User).filter(
            models.User.email == USER_PAYLOAD["email"]
        ).first()
        u.is_active = False
        db.commit()
    finally:
        db.close()
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 403


# ===================================================================
# 7. User isolation at database / model level
# ===================================================================

def test_user_isolation_model_layer():
    """AnalysisResult.user_id links records to specific users;
    queries scoped by user_id only return that user's records."""
    # Create two users
    client.post("/api/v1/auth/register", json=USER_PAYLOAD)
    client.post("/api/v1/auth/register", json={
        "username": "otheruser",
        "email": "other@example.com",
        "password": "OtherPass123!",
    })
    db = database.SessionLocal()
    try:
        user1 = db.query(models.User).filter(
            models.User.username == "testuser"
        ).first()
        user2 = db.query(models.User).filter(
            models.User.username == "otheruser"
        ).first()
        # Insert analysis records for each user
        a1 = models.AnalysisResult(
            user_id=user1.id, url="https://a.com",
            risk_score=10.0, risk_level="LOW"
        )
        a2 = models.AnalysisResult(
            user_id=user2.id, url="https://b.com",
            risk_score=80.0, risk_level="CRITICAL"
        )
        db.add_all([a1, a2])
        db.commit()
        # User-scoped queries
        u1_results = db.query(models.AnalysisResult).filter(
            models.AnalysisResult.user_id == user1.id
        ).all()
        u2_results = db.query(models.AnalysisResult).filter(
            models.AnalysisResult.user_id == user2.id
        ).all()
        assert len(u1_results) == 1
        assert u1_results[0].url == "https://a.com"
        assert len(u2_results) == 1
        assert u2_results[0].url == "https://b.com"
    finally:
        db.close()


# -------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------

def teardown_module(module):
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
