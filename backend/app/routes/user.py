import logging
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, status, Request
from app.core.logging import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.core.database import get_db
from app.services.user import create_user, authenticate_user, get_user_details, send_reset_password_otp, reset_password, change_user_password
from app.schemas.user import UserCreate, ChangePasswordRequest, ChangePasswordResponse
from app.core.security import create_access_token, create_refresh_token, get_current_user
from app.utils.send_notifications.send_otp import verify_otp
from app.models.user import User
import random
from app.utils.send_notifications.send_otp import send_otp_email
from fastapi.security import OAuth2PasswordRequestForm
from jwt import ExpiredSignatureError, InvalidTokenError
from app.core.security import *


router = APIRouter()


@router.post("/", response_model=dict, summary="Create new User Registration")
async def register_user(user: UserCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    try:
        new_user = await create_user(db, user.name, user.email, user.mobile, user.password, background_tasks)
        logging.info(f"User registered successfully: {new_user.user_id}")

        return {
            "status_code": 200,
            "message": "User registered successfully. Please verify OTP sent to your email.",
            "access_token": new_user.access_token,
            "refresh_token": new_user.refresh_token,
            "user_data": {
                "id": new_user.id,
                "user_id": new_user.user_id,
                "name": new_user.name,
                "mobile": new_user.mobile,
                "is_active": new_user.is_active,
                "otp": new_user.otp,
                "verified_at": new_user.verified_at,
                "created_on": new_user.created_on,
                "updated_on": new_user.updated_on,
            }
        }

    except HTTPException as http_ex:
        logging.error(f"HTTP Exception during user registration: {http_ex.detail}")
        raise http_ex
    except Exception as ex:
        logging.error(f"Unexpected error during user registration: {str(ex)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post("/verify-otp/", response_model=dict, summary="Verify OTP for User Activation")
async def verify_user_otp(id: int, otp: str, db: AsyncSession = Depends(get_db)):
    try:
        user = await db.execute(select(User).filter(User.id == id))
        user = user.scalar_one_or_none()
        
        # Verify the USER
        if not user:
            logging.error(f"User not found with user_id: {id}")
            raise HTTPException(status_code=404, detail="User not found")

        # Verify the OTP
        if not await verify_otp(user.email, otp):
            logging.warning(f"Invalid OTP for user: {user.id}")
            raise HTTPException(status_code=400, detail="Invalid OTP")

        # Activate the user
        user.is_active = True
        user.verified_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)

        logging.info(f"User {id} verified successfully.")

        # Return success message and tokens
        return {
            "status_code": 200,
            "message": "User verified successfully and activated.",
            "data": {
                "access_token": user.access_token,
                "refresh_token": user.refresh_token,
                "user_data": {
                    "id": user.id,
                    "user_id": user.user_id,
                    "name": user.name,
                    "mobile": user.mobile,
                    "is_active": user.is_active,
                    "otp": user.otp,
                    "verified_at": user.verified_at,
                    "created_on": user.created_on,
                    "updated_on": user.updated_on,
                }
            }
        }
    except HTTPException as http_ex:
        logging.error(f"HTTP Exception during OTP verification for user_id {id}: {http_ex.detail}")
        raise http_ex
    except Exception as ex:
        logging.error(f"Unexpected error during OTP verification for user_id {id}: {str(ex)}")
        raise HTTPException(
            status_code=500, detail="An unexpected error occurred during OTP verification")


@router.post("/resend-otp/", response_model=dict, summary="Resend OTP for User")
async def resend_otp(
    id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    try:
        # Fetch user from the database
        user_result = await db.execute(select(User).filter(User.id == id))
        user = user_result.scalar_one_or_none()

        # Check if the user exists
        if not user:
            logging.error(f"User not found with id: {id}")
            raise HTTPException(status_code=404, detail="User not found")

        # Check if the user is already active
        if user.is_active:
            logging.warning(f"Attempt to resend OTP for an already active user: {id}")
            raise HTTPException(status_code=400, detail="User is already active")
            

        # Generate a new 6-digit OTP
        otp_code = str(random.randint(100000, 999999))
        user.otp = otp_code

        # Update the user in the database
        db.add(user)
        await db.commit()
        await db.refresh(user)

        # Send OTP email in the background
        await send_otp_email(background_tasks, user.name, user.email, otp_code)

        logging.info(f"Resent OTP to {user.email}")

        # Prepare the response
        return {
            "status_code": 200,
            "message": "New OTP sent to your email.",
            "access_token": user.access_token,
            "refresh_token": user.refresh_token,
            "user_data": {
                "id": user.id,
                "user_id": user.user_id,
                "name": user.name,
                "mobile": user.mobile,
                "is_active": user.is_active,
                "otp": user.otp,
                "verified_at": user.verified_at,
                "created_on": user.created_on,
                "updated_on": user.updated_on,
            }
        }
    except HTTPException as http_ex:
        logging.error(f"HTTP Exception during OTP resend: {http_ex.detail}")
        raise http_ex
    except Exception as ex:
        logging.error(f"Unexpected error during OTP resend: {str(ex)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post("/login/", summary="Login for User")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    try:
        # Authenticate user and get the response
        auth_response = await authenticate_user(db, form_data.username, form_data.password)

        if auth_response['status'] == "error":
            logging.warning(f"Login failed for user: {form_data.username}. {auth_response['msg']}")
            # Directly raise the appropriate HTTPException based on the authentication response
            raise HTTPException(status_code=400, detail=auth_response['msg'])

        user = auth_response['data']

        # Check if the user has existing tokens
        if user.access_token and user.refresh_token:
            return {
                "status": "success",
                "msg": "Login successful.",
                "access_token": user.access_token,
                "refresh_token": user.refresh_token,
                "user_data": {
                    "id": user.id,
                    "user_id": user.user_id,
                    "name": user.name,
                    "mobile": user.mobile,
                    "is_active": user.is_active,
                    "otp": user.otp,
                    "verified_at": user.verified_at,
                    "created_on": user.created_on.isoformat(),
                    "updated_on": user.updated_on.isoformat() if user.updated_on else None,
                }
            }

        # Generate new tokens if not found
        access_token = create_access_token(data={"sub": user.user_id})
        refresh_token = create_refresh_token(data={"sub": user.user_id})

        # Update the user with new tokens
        user.access_token = access_token
        user.refresh_token = refresh_token
        await db.commit()

        return {
            "status": "success",
            "msg": "Login successful. New tokens generated.",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_data": {
                "id": user.id,
                "user_id": user.user_id,
                "name": user.name,
                "mobile": user.mobile,
                "is_active": user.is_active,
                "otp": user.otp,
                "verified_at": user.verified_at,
                "created_on": user.created_on.isoformat(),
                "updated_on": user.updated_on.isoformat() if user.updated_on else None,
            }
        }
    except HTTPException as http_ex:
        # If an HTTPException occurs, log the error but don't raise a new one
        logging.error(f"HTTP Exception during login process: {str(http_ex)}")
        raise http_ex
    except Exception as ex:
        logging.error(f"Unexpected error during login process: {str(ex)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    

@router.get("/me/", response_model=dict, summary="Get details of the authenticated user")
async def get_authenticated_user(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    try:
        user_details = await get_user_details(db, current_user.user_id)

        if not user_details.is_active:
            logging.warning(f"User {current_user.id} is inactive.")
            raise HTTPException(status_code=403, detail="User account is inactive")

        return {
            "msg": "User details fetched successfully.",
            "status": "success",
            "data": {
                "id": user_details.id,
                "user_id": user_details.user_id,
                "name": user_details.name,
                "email": user_details.email,
                "mobile": user_details.mobile,
                "is_active": user_details.is_active,
                "otp": user_details.otp,
                "verified_at": user_details.verified_at.isoformat(),
                "created_on": user_details.created_on.isoformat(),
                "updated_on": user_details.updated_on.isoformat() if user_details.updated_on else None,
            }
        }
    except HTTPException as http_ex:
        logging.error(f"HTTP Exception fetching authenticated user details: {str(http_ex)}")
        raise http_ex
    except Exception as ex:
        logging.error(f"Error fetching authenticated user details: {str(ex)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

       
@router.post("/token/refresh", response_model=dict, summary="Refresh the access token using a valid refresh token.")
async def refresh_access_token(refresh_token: str, db: AsyncSession = Depends(get_db)):
    try:
        # Decode the refresh token
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")

        if user_id is None:
            logging.warning("Refresh token validation failed: user_id is None.")
            return {
                "msg": "Could not validate credentials",
                "status": "error",
                "data": {
                    "detail": "User ID is missing in token payload"
                }
            }

        # Fetch the user from the database
        result = await db.execute(select(User).filter(User.user_id == user_id))
        user = result.scalar_one_or_none()

        if user is None:
            logging.warning(f"Refresh token validation failed: user not found for user_id: {user_id}.")
            return {
                "msg": "Could not validate credentials",
                "status": "error",
                "data": {
                    "detail": "User not found for user_id"
                }
            }

        # Create a new access token
        new_access_token = create_access_token(data={"sub": user.user_id})
        new_refresh_token = create_refresh_token(data={"sub": user.user_id})

        # Update the user's refresh token in the database
        user.access_token = new_access_token
        user.refresh_token = new_refresh_token
        db.add(user)
        await db.commit()

        # Log successful token refresh
        logging.info(f"Successfully refreshed access token for user: {user_id}.")

        return {
            "msg": "Access token refreshed successfully.",
            "status": "success",
            "data": {
                "access_token": new_access_token,
                "token_type": "bearer",
                "refresh_token": new_refresh_token
            }
        }

    except ExpiredSignatureError:
        logging.warning("Refresh token has expired.")
        return {
            "msg": "Refresh token expired",
            "status": "error",
            "data": {
                "detail": "Refresh token has expired, please login again."
            }
        }
    except InvalidTokenError:
        logging.error("Invalid refresh token provided.")
        return {
            "msg": "Invalid refresh token",
            "status": "error",
            "data": {
                "detail": "Invalid refresh token"
            }
        }
    except Exception as e:
        logging.error(f"Internal server error during refresh token process: {str(e)}")
        return {
            "msg": "Internal server error",
            "status": "error",
            "data": {
                "detail": str(e)
            }
        }


@router.post("/forgot-password/", summary="Forgot password for user")
async def forgot_password(request: Request, identifier: str, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    try:
        # Call the service function for sending OTP
        result = await send_reset_password_otp(db, identifier, background_tasks, request)

        # Return success response
        return {
            "msg": "OTP sent to your registered email.",
            "status": "success",
            "data": {
                "email": result.get("email")
            }
        }

    except HTTPException as ex:
        # Handle known errors
        logging.error(f"Forgot password error: {str(ex)}")
        return {
            "msg": ex.detail,
            "status": "error",
            "data": {
                "detail": str(ex)
            }
        }

    except Exception as ex:
        # Handle unexpected errors
        logging.error(f"Internal server error in forgot password: {str(ex)}")
        return {
            "msg": "Internal server error",
            "status": "error",
            "data": {
                "detail": str(ex)
            }
        }


@router.post("/reset-password/", summary="Reset password using OTP")
async def reset_password_endpoint(identifier: str, otp: str, new_password: str, db: AsyncSession = Depends(get_db)):
    try:
        user = await reset_password(db, identifier, otp, new_password)

        # Prepare success response
        return {
            "msg": "Password reset successful",
            "status_code": 200,
            "data": {
                "id": user.id,
                "user_id": user.user_id,
                "name": user.name,
                "email": user.email,
                "mobile": user.mobile,
                "is_active": user.is_active,
                "created_on": user.created_on,
                "updated_on": user.updated_on
            }
        }

    except HTTPException as ex:
        # Log and return the specific error (invalid email/mobile or OTP)
        logging.error(f"Reset password error: {str(ex.detail)}")
        return {
            "msg": ex.detail,
            "status_code": ex.status_code,
            "data": None
        }

    except Exception as ex:
        # Handle any other unexpected errors
        logging.error(f"Unexpected error in reset password endpoint: {str(ex)}")
        return {
            "msg": "Internal server error.",
            "status_code": 500,
            "data": None
        }


@router.post("/change-password/", response_model=dict, summary="Change User Password")
async def change_password(
    request: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        user_id = current_user.id
        await change_user_password(db, user_id, request.current_password, request.new_password, request.confirm_new_password)

        # Return a structured response for a successful password change
        return {
            "status_code": 200,
            "msg": "Password changed successfully"
        }

    except HTTPException as http_ex:
        logging.error(f"HTTP error: {http_ex.detail}")
        return {
            "status_code": http_ex.status_code,
            "msg": http_ex.detail 
        }

    except Exception as ex:
        logging.error(f"Failed to change password: {str(ex)}", exc_info=True)
        return {
            "status_code": 500,
            "msg": "Failed to change password"
        }


@router.post("/logout", summary="User logout")
async def logout(token: str = Depends(oauth2_scheme)):
    try:
        # Add the token to the blacklist
        blacklist.add(token)
        logging.info(f"Token blacklisted successfully: {token}")
        return {"status_code": 200, "msg": "Logged out successfully"}
    except JWTError as jwt_ex:
        logging.error(f"JWT Error during logout: {str(jwt_ex)}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as ex:
        logging.error(f"Unexpected error during logout: {str(ex)}")
        raise HTTPException(
            status_code=500, detail="An unexpected error occurred during logout")
