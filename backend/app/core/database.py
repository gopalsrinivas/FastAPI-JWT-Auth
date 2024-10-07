from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
from sqlalchemy.exc import SQLAlchemyError
from app.core.logging import logging
from sqlalchemy.orm import declarative_base

# Set up database engine and session
engine = create_async_engine(settings.DATABASE_URL, echo=True)
async_session = sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()

# Dependency to get the database session
async def get_db() -> AsyncSession:
    session: AsyncSession = async_session()
    try:
        async with session:
            yield session
    except SQLAlchemyError as e:
        logging.error(f"Database error: {str(e)}", exc_info=True)
        raise
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}", exc_info=True)
        raise
    finally:
        await session.close()
