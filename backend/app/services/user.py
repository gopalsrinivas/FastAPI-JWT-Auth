from app.core.logging import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastapi import HTTPException, BackgroundTasks
from app.models.user import User
from app.core.security import hash_password
from sqlalchemy import func
from app.utils.send_notifications.send_otp import send_otp_email


async def generate_user_id(db: AsyncSession) -> str:
    try:
        result = await db.execute(select(func.max(User.id)))
        max_id = result.scalar_one_or_none()
        new_id = (max_id + 1) if max_id is not None else 1
        logging.info(f"Generated new user ID: user_{new_id}")
        return f"user_{new_id}"
    except Exception as e:
        logging.error(f"Error generating user ID: {str(e)}")
        raise HTTPException(status_code=500, detail="Error generating user ID")


async def create_user(db: AsyncSession, name: str, email: str, mobile: str, password: str, background_tasks: BackgroundTasks) -> User:
    try:
        # Check if the email already exists
        existing_email = await db.execute(select(User).filter(User.email == email))
        if existing_email.scalar_one_or_none():
            logging.warning(
                f"Registration attempt with existing email: {email}")
            raise HTTPException(status_code=400, detail="Email already exists")

        # Check if the mobile number already exists
        existing_mobile = await db.execute(select(User).filter(User.mobile == mobile))
        if existing_mobile.scalar_one_or_none():
            logging.warning(
                f"Registration attempt with existing mobile number: {mobile}")
            raise HTTPException(
                status_code=400, detail="Mobile number already exists")

        # Generate new user ID
        user_id = await generate_user_id(db)

        # Hash the password
        hashed_password = hash_password(password)
        logging.info(f"Password hashed successfully for user: {name}")

        # Create new user instance
        new_user = User(
            user_id=user_id,
            name=name,
            email=email,
            mobile=mobile,
            password=hashed_password,
            is_active=False
        )

        # Add user to the database
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        logging.info(f"User created successfully: {new_user}")

        # Send OTP to the user’s email
        await send_otp_email(background_tasks, new_user.name, new_user.email)

        return new_user

    except HTTPException as e:
        logging.error(f"HTTP Exception occurred: {str(e)}")
        raise e

    except Exception as e:
        logging.error(f"Error occurred while creating user: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred during user creation")
