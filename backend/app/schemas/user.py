from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    mobile: str
    password: str
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "name": "Your Name",
                "email": "your_email@example.com",
                "mobile": "1234567890",
                "password": "your_password"
            }
        }


class UserResponse(BaseModel):
    id: int
    user_id: str
    name: str
    email: str
    mobile: str
    is_active: bool
    verified_at: Optional[datetime] = None
    created_on: datetime
    updated_on: Optional[datetime] = None

class ResetPasswordRequest(BaseModel):
    identifier: str
    otp: str
    new_password: str
    

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(...,
                                  description="Current password of the user")
    new_password: str = Field(..., description="New password to be set")
    confirm_new_password: str = Field(...,
                                      description="Confirmation of the new password")


class ChangePasswordResponse(BaseModel):
    id: int
    message: str
