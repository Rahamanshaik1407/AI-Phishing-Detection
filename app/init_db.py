"""
Initialize the application database.
"""

from app.database import Base
from app.database import engine

from app.models import AnalysisResult


def initialize_database():
    """
    Create all database tables.
    """

    Base.metadata.create_all(
        bind=engine
    )


if __name__ == "__main__":

    initialize_database()

    print(
        "Database initialized successfully."
    )
