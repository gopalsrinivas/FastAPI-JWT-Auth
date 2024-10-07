import os
import random
from app.core.logging import logging
from fastapi import APIRouter, BackgroundTasks, Request, Form, HTTPException
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from fastapi.templating import Jinja2Templates
from app.core.config import settings
from jinja2 import TemplateError

# Set up the templates directory
templates = Jinja2Templates(directory="app/utils/templates")

# Initialize FastMail with settings
conf = FastMail(
    ConnectionConfig(
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
)

# Create APIRouter instance
router = APIRouter()

# Contact Form Function
async def send_contact_form(
    background_tasks: BackgroundTasks,
    name: str,
    email: str,
    esubject: str,
    message: str,
    request: Request
):
    try:
        # Render the contact form email body using Jinja2
        subject = "Contact Form Submission"
        try:
            contact_body = templates.get_template("contactform.html").render(
                {"name": name, "email": email,"subject": esubject, "message": message})
        except TemplateError as e:
            logging.error(f"Error rendering contact form template: {str(e)}")
            raise HTTPException(status_code=500, detail="Template rendering failed")

        # Define CC recipients
        cc_emails = ["gopalsrinivas29@gmail.com",
                     "gopalsrinivasb.29@gmail.com"]

        # Create the email message
        contact_message = MessageSchema(
            subject=subject,
            recipients=[email],
            cc=cc_emails,
            body=contact_body,
            subtype="html"
        )

        # Add task to send email in background
        background_tasks.add_task(conf.send_message, contact_message)
        logging.info(f"Contact form email sent to {email}")
        return {"message": "Contact form email sent successfully."}
    except HTTPException as http_exc:
        logging.warning(f"HTTP Exception occurred: {str(http_exc)}")
        raise http_exc
    except Exception as e:
        logging.error(f"Error sending contact form email: {str(e)}")
        raise HTTPException(status_code=500, detail="Error sending contact form email")

# Define endpoints and bind functions
@router.post("/send-contact-email/", summary="Send contact form email")
async def contact_email_api(
    background_tasks: BackgroundTasks,
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    subject: str = Form(...),
    message: str = Form(...)
):
    return await send_contact_form(
        background_tasks=background_tasks,
        name=name,
        email=email,
        esubject=subject,
        message=message,
        request=request
    )

# OTP Email Function
# Utility function to generate a 6-digit OTP
def generate_otp():
    return random.randint(100000, 999999)

async def send_otp_email(
    background_tasks: BackgroundTasks,
    name: str,
    email: str,
    request: Request
):
    try:
        # Generate a 6-digit OTP
        otp_code = generate_otp()

        # Render the OTP email body using Jinja2
        subject = "OTP Verification"
        try:
            otp_body = templates.get_template("otp.html").render({"name": name, "otp_code": otp_code})
        except TemplateError as e:
            logging.error(f"Error rendering OTP template: {str(e)}")
            raise HTTPException(status_code=500, detail="Template rendering failed")

        # Define CC recipients
        cc_emails = ["gopalsrinivas29@gmail.com",
                     "gopalsrinivasb.29@gmail.com"]

        # Create the OTP email message
        otp_message = MessageSchema(
            subject=subject,
            recipients=[email],
            cc=cc_emails,
            body=otp_body,
            subtype="html"
        )

        # Add task to send OTP email in the background
        background_tasks.add_task(conf.send_message, otp_message)
        logging.info(f"OTP email sent to {email} (OTP not logged for security reasons)")
        return {"message": "OTP email sent successfully."}
    except HTTPException as http_exc:
        logging.warning(f"HTTP Exception occurred: {str(http_exc)}")
        raise http_exc
    except Exception as e:
        logging.error(f"Error sending OTP email: {str(e)}")
        raise HTTPException(status_code=500, detail="Error sending OTP email")


# Define OTP email API route
@router.post("/send-otp-email/", summary="Send OTP email")
async def otp_email_api(
    background_tasks: BackgroundTasks,
    request: Request,
    name: str = Form(...),
    email: str = Form(...)
):
    return await send_otp_email(
        background_tasks=background_tasks,
        name=name,
        email=email,
        request=request
    )
