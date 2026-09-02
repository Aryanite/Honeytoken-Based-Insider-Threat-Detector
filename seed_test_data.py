"""Seed script to populate initial sample honeytokens for local development and testing."""

import sys
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
        "description": "Planted in engineering developer workstation repository in .env",
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
        "description": "Synthetic database user entry inserted into production payroll database",
        "placement_location": "db://corporate-db/users/user_id=9999",
    },
    {
        "name": "Deprecated Stripe Integration Secret",
        "token_type": "api_key",
        "criticality": 15,
        "status": "revoked",
        "description": "Revoked token used to verify that revoked honeytokens do not generate active alerts",
        "placement_location": "wiki://engineering/deprecated_keys",
    },
]


def seed_database():
    print(f"Connecting to database: {settings.DATABASE_URL}")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        created_count = 0
        for data in SAMPLE_TOKENS:
            existing = db.query(HoneyToken).filter(HoneyToken.name == data["name"]).first()
            if not existing:
                token = HoneyToken(**data)
                db.add(token)
                db.commit()
                db.refresh(token)
                created_count += 1
                print(f"[+] Created Honeytoken: {token.name}")
                print(f"    - ID: {token.token_id}")
                print(f"    - Type: {token.token_type} | Criticality: {token.criticality} | Status: {token.status}")
                print(f"    - Beacon URL: {build_beacon_url(token.token_id)}\n")
            else:
                print(f"[*] Already exists: {existing.name} (ID: {existing.token_id})")

        print(f"Seeding completed. {created_count} new honeytokens created.")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
