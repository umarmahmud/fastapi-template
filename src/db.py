import os
from dotenv import load_dotenv

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

load_dotenv()

user = os.getenv("POSTGRES_USER")
password = os.getenv("POSTGRES_PASSWORD")
database = os.getenv("POSTGRES_DATABASE")


db_url = f'postgresql+psycopg2://{user}:{password}@db/{database}'
engine = create_engine(db_url, echo=True)
Session = sessionmaker(bind=engine)


def get_db():
    with Session() as session:
        yield session