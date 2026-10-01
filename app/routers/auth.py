"""
Authentication router exposing registration, login, user info, and password change endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import auth as auth_utils
from app import schemas
from app import models
from app.database import get_db

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=schemas.TokenResponse)
def register(user: schemas.UserRegister, db: Session = Depends(get_db)):
    """Register a new user.

    - Validates uniqueness of username and email.
    - Hashes the password with Argon2id.
    - Returns a JWT access token and safe user info.
    """
    # Check for duplicates
    if (
        db.query(models.User)
        .filter((models.User.username == user.username) | (models.User.email == user.email))
        .first()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered.",
        )

    password_hash = auth_utils.hash_password(user.password)
    db_user = models.User(
        username=user.username,
        email=user.email,
        password_hash=password_hash,
        is_active=True,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    access_token = auth_utils.create_access_token(data={"sub": str(db_user.id)})
    return schemas.TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=schemas.UserResponse.model_validate(db_user),
    )


@router.post("/login", response_model=schemas.TokenResponse)
def login(credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    """Authenticate a user and issue a JWT token.

    Allows login with either email or username.
    """
    user = (
        db.query(models.User)
        .filter(
            (models.User.email == credentials.email_or_username)
            | (models.User.username == credentials.email_or_username)
        )
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )
    if not auth_utils.verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth_utils.create_access_token(data={"sub": str(user.id)})
    return schemas.TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=schemas.UserResponse.model_validate(user),
    )


@router.get("/me", response_model=schemas.UserResponse)
def read_current_user(current_user: models.User = Depends(auth_utils.get_current_user)):
    """Return the authenticated user's information."""
    return schemas.UserResponse.model_validate(current_user)


@router.post("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    payload: schemas.PasswordChange,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth_utils.get_current_user),
):
    """Allow a logged‑in user to change their password.

    - Verifies the current password.
    - Hashes and stores the new password.
    """
    if not auth_utils.verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    new_hash = auth_utils.hash_password(payload.new_password)
    current_user.password_hash = new_hash
    db.add(current_user)
    db.commit()
    return {"detail": "Password changed successfully."}
