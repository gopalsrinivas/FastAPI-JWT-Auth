import random
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from fastapi import HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.templating import Jinja2Templates
from app.core.logging import logging
from app.core.config import settings
from datetime import datetime, timedelta
from jinja2 import TemplateError  # Import TemplateError
import os
from pathlib import Path

otp_store = {}

# Correctly set the templates directory using absolute path
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
TEMPLATES_DIR = BASE_DIR / "app" / "utils" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

conf = ConnectionConfig(
    MAIL_USERNAME=settings.EMAIL_HOST_USER,
    MAIL_PASSWORD=settings.EMAIL_HOST_PASSWORD,
    MAIL_FROM=settings.EMAIL_HOST_USER,
    MAIL_FROM_NAME=settings.MAIN_FROM_NAME,
    MAIL_PORT=settings.EMAIL_PORT,
    MAIL_SERVER=settings.EMAIL_HOST,
    MAIL_STARTTLS=settings.EMAIL_USE_TLS,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True
)

fast_mail = FastMail(conf)

# Utility function to generate a 6-digit OTP


def generate_otp():
    return random.randint(100000, 999999)


async def send_otp_email(background_tasks, name: str, email: str, otp_code: int):
    try:
        # Store OTP temporarily with expiration (10 minutes)
        otp_store[email] = {
            "otp": otp_code,
            "expires": datetime.utcnow() + timedelta(minutes=10)
        }
        # Render the OTP email body using Jinja2
        try:
            otp_body = templates.get_template("send_otp.html").render({"name": name, "otp_code": otp_code})
        except TemplateError as e:
            logging.error(f"Error rendering OTP template: {str(e)}")
            raise HTTPException(status_code=500, detail="Template rendering failed")

        subject = "OTP Verification"

        message = MessageSchema(
            subject=subject,
            recipients=[email],
            body=otp_body,
            subtype="html"
        )

        # Send email in background
        background_tasks.add_task(fast_mail.send_message, message)
        logging.info(f"OTP email sent to {email}")
    except Exception as e:
        logging.error(f"Error sending OTP email: {str(e)}")
        raise HTTPException(status_code=500, detail="Error sending OTP email")


async def verify_otp(email: str, otp: str) -> bool:
    try:
        if email in otp_store:
            stored_otp = otp_store[email]
            logging.info(f"Stored OTP for {email}: {stored_otp['otp']}, Expires at: {stored_otp['expires']}")

            # Check if OTP is valid and not expired
            if datetime.utcnow() < stored_otp["expires"] and stored_otp["otp"] == otp:
                # OTP is valid; remove it from store
                logging.info(f"OTP verified successfully for {email}")
                del otp_store[email]  # Remove OTP once validated
                return True
            else:
                logging.warning(f"OTP expired or invalid for email: {email}")
                return False
        else:
            logging.warning(f"OTP not found for email: {email}")
            return False
    except Exception as e:
        logging.error(f"Error verifying OTP: {str(e)}")
        raise HTTPException(status_code=500, detail="Error verifying OTP")
