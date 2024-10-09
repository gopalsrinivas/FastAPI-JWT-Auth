from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from app.core.config import settings
from app.core.logging import logging
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.models.user import User
from sqlalchemy.future import select
from jwt import InvalidTokenError, ExpiredSignatureError, PyJWTError

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
blacklist = set()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Secret key to encode and decode JWT tokens
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 1 day
REFRESH_TOKEN_EXPIRE_DAYS = 7


def hash_password(password: str) -> str:
    try:
        hashed_pw = pwd_context.hash(password)
        logging.info("Password hashed successfully.")
        return hashed_pw
    except Exception as ex:
        logging.error(f"Error hashing password: {str(ex)}")
        raise Exception("Failed to hash password")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        if pwd_context.verify(plain_password, hashed_password):
            logging.info("Password verification successful.")
            return True
        else:
            logging.warning("Password verification failed.")
            return False
    except Exception as ex:
        logging.error(f"Error verifying password: {str(ex)}")
        raise Exception("Failed to verify password")


def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + \
            (expires_delta if expires_delta else timedelta(
                minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})

        # Encoding JWT
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logging.info(f"Access token created successfully for user: {
                     data.get('sub')}")
        return encoded_jwt
    except JWTError as jwt_ex:
        logging.error(f"JWT Error during access token creation: {str(jwt_ex)}")
        raise HTTPException(
            status_code=500, detail="Failed to create access token")
    except Exception as ex:
        logging.error(
            f"Unexpected error during access token creation: {str(ex)}")
        raise HTTPException(
            status_code=500, detail="Failed to create access token")


def create_refresh_token(data: dict) -> str:
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire})
        # Encoding JWT
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logging.info(f"Refresh token created successfully for user: {
                     data.get('sub')}")
        return encoded_jwt
    except JWTError as jwt_ex:
        logging.error(
            f"JWT Error during refresh token creation: {str(jwt_ex)}")
        raise JWTError("Failed to create refresh token")
    except Exception as ex:
        logging.error(
            f"Unexpected error during refresh token creation: {str(ex)}")
        raise Exception("Failed to create refresh token")


async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")

        if user_id is None:
            logging.warning("User ID is missing in token payload.")
            raise credentials_exception

        # Fetch user from the database
        result = await db.execute(select(User).filter(User.user_id == user_id))
        user = result.scalar_one_or_none()

        if user is None:
            logging.warning(f"User not found for user_id: {user_id}.")
            raise credentials_exception

        logging.info(f"User {user_id} successfully authenticated.")
        return user

    except ExpiredSignatureError:
        logging.warning("Token has expired.")
        raise HTTPException(status_code=401, detail="Token has expired, please login again.", headers={
                            "WWW-Authenticate": "Bearer"})
    except InvalidTokenError:
        logging.error("Invalid token provided.")
        raise HTTPException(status_code=401, detail="Invalid token", headers={
                            "WWW-Authenticate": "Bearer"})
    except PyJWTError as e:
        logging.error(f"JWT error: {str(e)}")
        raise credentials_exception
    except Exception as e:
        logging.error(f"Internal server error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error", headers={
                            "WWW-Authenticate": "Bearer"})
