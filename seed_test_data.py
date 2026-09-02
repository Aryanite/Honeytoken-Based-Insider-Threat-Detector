"""
Seed script: populate the development database with representative sample honeytokens.

Run once after first launch:
    python seed_test_data.py
"""

from backend.core.config import settings
from backend.db.base import Base
from backend.db.session import engine, SessionLocal
from backend.models.token import HoneyToken
from backend.schemas.token import build_beacon_url


SAMPLE_TOKENS = [
    {
        "name": "AWS Production S3 Read Access Key",
        "token_type": "api_key",
        "criticality": 45,
        "status": "active",
        "description": "Planted in engineering workstation repository .env file",
        "placement_location": "repo://backend-service/.env",
    },
    {
        "name": "Q3 Executive Compensation & Bonus Plan",
        "token_type": "canary_doc",
        "criticality": 40,
        "status": "active",
        "description": "Word document with embedded tracking pixel placed in shared HR directory",
        "placement_location": "//corp-share/hr/compensation/2026_q3_exec_bonus.docx",
    },
    {
        "name": "Payroll Admin Database Honeytoken Record",
        "token_type": "db_record",
        "criticality": 50,
        "status": "active",
        "description": "Synthetic database entry inserted into the production payroll database",
        "placement_location": "db://corporate-db/users/user_id=9999",
    },
    {
        "name": "Deprecated Stripe Integration Secret",
        "token_type": "api_key",
        "criticality": 15,
        "status": "revoked",
        "description": "Revoked token — verifies that revoked honeytokens do not generate active alerts",
        "placement_location": "wiki://engineering/deprecated_keys",
    },
]


def seed_database() -> None:
    """Create DB tables if they do not exist, then insert sample honeytokens."""
    print(f"Database: {settings.DATABASE_URL}")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    created_count = 0
    try:
        for data in SAMPLE_TOKENS:
            existing = (
                db.query(HoneyToken)
                .filter(HoneyToken.name == data["name"])
                .first()
            )
            if existing:
                print(f"[=] Already exists: {existing.name} (ID: {existing.token_id})")
                continue

            token = HoneyToken(**data)
            db.add(token)
            db.commit()
            db.refresh(token)
            created_count += 1
            print(f"[+] Created: {token.name}")
            print(f"    ID          : {token.token_id}")
            print(f"    Type        : {token.token_type}")
            print(f"    Criticality : {token.criticality}")
            print(f"    Status      : {token.status}")
            print(f"    Beacon URL  : {build_beacon_url(token.token_id)}")
            print()
    finally:
        db.close()

    print(f"Done. {created_count} honeytoken(s) created.")


if __name__ == "__main__":
    seed_database()
