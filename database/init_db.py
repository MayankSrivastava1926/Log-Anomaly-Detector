from database.database import engine, Base
from database.models import Scan


Base.metadata.create_all(bind=engine)

print("Database tables created successfully.")