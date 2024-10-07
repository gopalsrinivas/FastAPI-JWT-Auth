from sqlalchemy import Column, Integer, String, Boolean, DateTime, func
from app.core.database import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), nullable=False, unique=True)
    name = Column(String(150))
    email = Column(String(150), unique=True, index=True)
    mobile = Column(String(150), unique=True, index=True)
    password = Column(String(150))
    access_token = Column(String(500), nullable=True)
    refresh_token = Column(String(500), nullable=True)
    otp = Column(String(6), nullable=True)
    is_active = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True, default=None)
    created_on = Column(DateTime, default=func.now(), nullable=False)
    updated_on = Column(DateTime, onupdate=func.now(), default=None)

    def __repr__(self):
        return f"<User {self.name} (ID: {self.user_id}) created on {self.created_on}>"
