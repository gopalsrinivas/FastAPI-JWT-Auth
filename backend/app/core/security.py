from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from app.core.config import settings
from app.core.logging import logging

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Secret key to encode and decode JWT tokens
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
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
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})

        # Encoding JWT
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logging.info(f"Access token created successfully for user: {data.get('sub')}")
        return encoded_jwt
    except JWTError as jwt_ex:
        logging.error(f"JWT Error during access token creation: {str(jwt_ex)}")
        raise JWTError("Failed to create access token")
    except Exception as ex:
        logging.error(f"Unexpected error during access token creation: {str(ex)}")
        raise Exception("Failed to create access token")


def create_refresh_token(data: dict) -> str:
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire})
        # Encoding JWT
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logging.info(f"Refresh token created successfully for user: {data.get('sub')}")
        return encoded_jwt
    except JWTError as jwt_ex:
        logging.error(f"JWT Error during refresh token creation: {str(jwt_ex)}")
        raise JWTError("Failed to create refresh token")
    except Exception as ex:
        logging.error(f"Unexpected error during refresh token creation: {str(ex)}")
        raise Exception("Failed to create refresh token")