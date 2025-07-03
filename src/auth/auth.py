import os
from dotenv import load_dotenv
from typing import Annotated
from datetime import datetime, timedelta, timezone
import logging

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError

from sqlalchemy import select, insert
from sqlalchemy.orm import Session

from .model import UserTable, User, AdminUser, Token
from db import get_db

load_dotenv()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

password_context = CryptContext(schemes="bcrypt", bcrypt__rounds=12)

# used for encoding and decoding jwt tokens
secret_key = os.getenv("SECRET")
algorithm = "HS256"
token_expire_time = 15

# jwt claims
issuer = "company"
audience = "web-app"

router = APIRouter()

def find_user(db_session, username):
    stmt = select(UserTable).where(UserTable.username == username)
    result = db_session.execute(statement=stmt)
    user = result.scalars().first()
    if user:
        return user
    else:
        return None


def verify_password(password, hashed_password):
    return password_context.verify(password, hashed_password)


def get_password_hash(password):
    return password_context.hash(password)
    

def authenticate_user(db_session, username, password):
    user = find_user(db_session, username)
    if not user:
        return False
    if not verify_password(password, user.pwd):
        return False
    return user


def create_token(user: User):
    jwt_claims = {}
    jwt_claims.update({"iss": issuer})
    jwt_claims.update({"aud": audience})
    time_now = datetime.now(timezone.utc)
    expire = time_now + timedelta(minutes=token_expire_time)
    jwt_claims.update({"iat": time_now})
    jwt_claims.update({"nbf": time_now})
    jwt_claims.update({"exp": expire})
    jwt_claims.update({"sub": user.username})
    if user.admin_user:
        jwt_claims.update({"roles": ["standard", "admin"]})
    else:
        jwt_claims.update({"roles": ["standard"]})
    encoded_jwt = jwt.encode(jwt_claims, secret_key, algorithm=algorithm)
    return encoded_jwt


def get_current_user(db_session: Annotated[Session, Depends(get_db)], token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = find_user(db_session, username)
    if user is None:
        raise credentials_exception
    if "admin" in payload.get("roles"):
        return AdminUser(username=user.username, pwd=user.pwd, admin_user=user.admin_user)
    return user


def check_for_admin(user: Annotated[User, Depends(get_current_user)]):
    if type(user) is not AdminUser:
        raise HTTPException(status_code=401, detail="Not admin user")
    else:
        return user


# authenticates user, then creates a token based on supplying the correct username and password
@router.post("/login", response_model=Token)
def login(db_session: Annotated[Session, Depends(get_db)], form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(db_session, form_data.username, form_data.password)
    if not user:
        logging.warning(f'FAILED LOGIN ATTEMPT at {datetime.now(timezone.utc)} by {form_data.username}')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_token(user=user)
    return Token(access_token=access_token, token_type="Bearer")


@router.post("/signup")
def login(db_session: Annotated[Session, Depends(get_db)], form_data: Annotated[OAuth2PasswordRequestForm, Depends()], response: Response):
    user = find_user(db_session, form_data.username)
    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )
    username = form_data.username
    password = get_password_hash(form_data.password)
    stmt = insert(UserTable).values(
        username=username,
        pwd=password,
        admin_user=False
    )
    db_session.execute(stmt)
    db_session.commit()
    response.status_code = status.HTTP_201_CREATED
    return { "user": username }