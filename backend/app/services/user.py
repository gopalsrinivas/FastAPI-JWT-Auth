from app.core.logging import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastapi import Request,HTTPException, BackgroundTasks
from app.models.user import User
from app.core.security import verify_password,hash_password, create_access_token, create_refresh_token,get_current_user
from sqlalchemy import func, select, or_
from app.utils.send_notifications.send_otp import send_otp_email,send_reset_password_email
import random

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
            logging.warning(f"Registration attempt with existing email: {email}")
            raise HTTPException(status_code=400, detail="Email already exists")

        # Check if the mobile number already exists
        existing_mobile = await db.execute(select(User).filter(User.mobile == mobile))
        if existing_mobile.scalar_one_or_none():
            logging.warning(f"Registration attempt with existing mobile number: {mobile}")
            raise HTTPException(status_code=400, detail="Mobile number already exists")

        # Generate new user ID
        user_id = await generate_user_id(db)

        # Hash the password
        hashed_password = hash_password(password)
        logging.info(f"Password hashed successfully for user: {name}")
        
        # Generate a random 6-digit OTP
        otp_code = str(random.randint(100000, 999999))
        
        # Create new user instance
        new_user = User(
            user_id=user_id,
            name=name,
            email=email,
            mobile=mobile,
            password=hashed_password,
            is_active=False,
            otp=otp_code
        )
        
        # Add user to the database
        db.add(new_user)
        
        # Create tokens
        access_token = create_access_token(data={"sub": new_user.user_id})
        refresh_token = create_refresh_token(data={"sub": new_user.user_id})
        logging.info(f"Tokens created: {access_token} -- {refresh_token}")
        
        # Store tokens in the user instance
        new_user.access_token = access_token
        new_user.refresh_token = refresh_token

        # Commit the transaction
        await db.commit()
        
        # Refresh the user instance with the latest data from the DB
        await db.refresh(new_user)
        
        logging.info(f"User created successfully: {new_user}")

        # Send OTP to the user’s email in the background
        logging.info(f"Preparing to send OTP email to {new_user.email} with code {otp_code}")
        await send_otp_email(background_tasks, new_user.name, new_user.email, otp_code)

        return new_user

    except HTTPException as e:
        logging.error(f"HTTP Exception occurred: {str(e)}")
        raise e

    except Exception as e:
        logging.error(f"Error occurred while creating user: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred during user creation")


async def authenticate_user(db: AsyncSession, username: str, password: str):
    try:
        # Check if the username is an email or a mobile number
        user_result = await db.execute(select(User).filter((User.email == username) | (User.mobile == username)))
        user = user_result.scalar_one_or_none()

        if not user:
            logging.warning(f"User {username} not found.")
            return None

        if not verify_password(password, user.password):
            logging.warning(f"Password verification failed for user: {username}.")
            return None

        # Check if the user is active
        if not user.is_active:
            logging.warning(f"User {username} is not active.")
            return None

        return user
    except Exception as ex:
        logging.error(f"Error during user authentication: {str(ex)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


async def get_user_details(db: AsyncSession, user_id: str) -> User:
    try:
        user_result = await db.execute(select(User).filter(User.user_id == user_id))
        user = user_result.scalar_one_or_none()

        if not user:
            logging.warning(f"User not found: {user_id}.")
            raise HTTPException(status_code=404, detail="User not found")

        return user
    except Exception as ex:
        logging.error(f"Error fetching user details: {str(ex)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


async def send_reset_password_otp(db: AsyncSession, identifier: str, background_tasks: BackgroundTasks, request: Request):
    try:
        # Determine if the identifier is an email or a mobile number
        if "@" in identifier:
            # If it's an email
            result = await db.execute(select(User).filter(User.email == identifier))
        else:
            # Assuming it's a mobile number
            result = await db.execute(select(User).filter(User.mobile == identifier))

        user = result.scalar_one_or_none()

        if not user:
            logging.warning(f"User with identifier {identifier} not found")
            raise HTTPException(status_code=404, detail="User not found")

        otp_code = str(random.randint(100000, 999999))
        user.otp = otp_code
        await db.commit()

        # Get the base URL from the request
        base_url = f"{request.url.scheme}://{request.url.hostname}{':' +
                                                                   str(request.url.port) if request.url.port else ''}"

        # Pass base_url
        await send_reset_password_email(background_tasks, user.name, user.email, otp_code, base_url)
        logging.info(f"OTP sent to {user.email}")

        return {"message": "OTP sent to your registered email."}
    except Exception as ex:
        logging.error(f"Error while sending OTP: {str(ex)}")
        raise HTTPException(
            status_code=500, detail="Error occurred while sending OTP.")


async def reset_password(db: AsyncSession, identifier: str, otp: str, new_password: str):
    try:
        # Retrieve the user with the matching email or mobile and OTP
        result = await db.execute(select(User).filter((User.email == identifier) | (User.mobile == identifier), User.otp == otp))
        user = result.scalar_one_or_none()

        if not user:
            logging.warning(f"Invalid OTP or identifier: {identifier}")
            raise HTTPException(
                status_code=400, detail="Invalid OTP or identifier")

        # Hash the new password and update the user
        hashed_password = hash_password(new_password)
        user.password = hashed_password
        user.otp = None

        await db.commit()

        # Refresh the user object to get updated fields
        await db.refresh(user)

        logging.info(f"Password reset for user {user.email}")

        return {
            "message": "Password reset successful",
            "user": {
                "user_id": user.user_id,
                "name": user.name,
                "email": user.email,
                "mobile": user.mobile,
                "is_active": user.is_active,
                "created_on": user.created_on,
                "updated_on": user.updated_on
            }
        }
    except Exception as ex:
        logging.error(f"Error resetting password: {str(ex)}")
        raise HTTPException(
            status_code=500, detail="Error resetting password.")


async def change_user_password(db: AsyncSession, id: int, current_password: str, new_password: str, confirm_new_password: str):
    try:
        # Fetch the user by ID
        result = await db.execute(select(User).filter(User.id == id))
        user = result.scalar_one_or_none()

        if not user:
            logging.warning(f"User with ID {id} not found.")
            raise HTTPException(status_code=404, detail="User ID not found.")

        # Verify the current password
        if not verify_password(current_password, user.password):
            logging.warning(
                f"Current password verification failed for user: {id}.")
            raise HTTPException(
                status_code=400, detail="Current password is incorrect.")

        # Check if the new password and confirm password match
        if new_password != confirm_new_password:
            logging.warning("New password and confirmation do not match.")
            raise HTTPException(
                status_code=400, detail="New password and confirmation do not match.")

        # Hash the new password
        hashed_new_password = hash_password(new_password)

        # Update the user's password
        user.password = hashed_new_password
        await db.commit()
        logging.info(f"Password changed successfully for user: {id}.")

        # Return a response with the id and success message
        return {"id": user.id, "message": "Password changed successfully."}

    except HTTPException as ex:
        # Log and raise the HTTPException to be caught in the route handler
        logging.error(f"Error changing password for user {
                      id}: {ex.status_code}: {ex.detail}")
        raise ex  # Re-raise the exception to be handled in the route

    except Exception as e:
        logging.error(
            f"Unexpected error changing password for user {id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
