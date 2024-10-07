from app.core.logging import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.core.database import get_db
from app.services.user import create_user
from app.schemas.user import UserCreate
from app.core.security import create_access_token, create_refresh_token
from app.utils.send_notifications.send_otp import verify_otp
from app.models.user import User


router = APIRouter()


@router.post("/", response_model=dict, summary="Create new User Registration")
async def register_user(user: UserCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    try:
        new_user = await create_user(db, user.name, user.email, user.mobile, user.password, background_tasks)
        
        logging.info(f"User registered successfully: {new_user.user_id}")

        return {
            "message": "User registered successfully. Please verify OTP sent to your email.",
            "access_token": new_user.access_token,
            "refresh_token": new_user.refresh_token,
            "user_data": {
                "id": new_user.id,
                "user_id": new_user.user_id,
                "name": new_user.name,
                "mobile": new_user.mobile,
                "is_active": new_user.is_active,
                "verified_at": new_user.verified_at,
                "created_on": new_user.created_on,
                "updated_on": new_user.updated_on,
            }
        }

    except HTTPException as http_ex:
        logging.error(f"HTTP Exception during user registration: {
                      http_ex.detail}")
        raise http_ex
    except Exception as ex:
        logging.error(f"Unexpected error during user registration: {str(ex)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post("/verify-otp/", response_model=dict, summary="Verify OTP for User Activation")
async def verify_user_otp(id: int, otp: str, db: AsyncSession = Depends(get_db)):
    try:
        user = await db.execute(select(User).filter(User.id == id))
        user = user.scalar_one_or_none()

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
            "message": "User verified successfully and activated.",
            "access_token": user.access_token,
            "refresh_token": user.refresh_token,
            "user_data": {
                "id": user.id,
                "user_id": user.user_id,
                "name": user.name,
                "mobile": user.mobile,
                "is_active": user.is_active,
                "verified_at": user.verified_at,
                "created_on": user.created_on,
                "updated_on": user.updated_on,
            }
        }

    except HTTPException as http_ex:
        logging.error(f"HTTP Exception during OTP verification: {
                      http_ex.detail}")
        raise http_ex
    except Exception as ex:
        logging.error(f"Unexpected error during OTP verification: {str(ex)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
