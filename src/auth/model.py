from pydantic import BaseModel, Field
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# sqlalchemy models
class Base(DeclarativeBase):
    pass


class UserTable(Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(primary_key=True)
    pwd: Mapped[str]
    admin_user: Mapped[bool]


# pydantic models
class User(BaseModel):
    username: str
    pwd: str
    admin_user: bool


class AdminUser(User):
    pass


class Token(BaseModel):
    access_token: str
    token_type: str