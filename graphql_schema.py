# SENTRACARE-BE-AUTH/graphql_schema.py

import strawberry
from typing import List
from strawberry.fastapi import GraphQLRouter
from sqlalchemy.orm import Session
from models import User, RoleEnum, StatusEnum
from database import SessionLocal

@strawberry.type
class UserType:
    id: int
    username: str
    email: str
    role: str
    status: str

# Query root
@strawberry.type
class Query:
    @strawberry.field
    def active_admins_and_doctors(self, info) -> List[UserType]:
        db: Session = info.context["db"]
        users = (
            db.query(User)
            .filter(User.role.in_([RoleEnum.DOKTER, RoleEnum.SUPERADMIN]))
            .filter(User.status == StatusEnum.ACTIVE)
            .all()
        )

        return [
            UserType(
                id=u.id,
                username=u.username,
                email=u.email,
                role=u.role.value,
                status=u.status.value,
            )
            for u in users
        ]

    @strawberry.field
    def all_users(self, info) -> List[UserType]:
        db: Session = info.context["db"]
        # Ambil semua user tanpa filter role
        users = db.query(User).all()

        return [
            UserType(
                id=u.id,
                username=u.username,
                email=u.email,
                role=u.role.value,
                status=u.status.value,
            )
            for u in users
        ]

schema = strawberry.Schema(query=Query)

def get_context():
    db = SessionLocal()
    return {"db": db}

# Router untuk FastAPI
graphql_app = GraphQLRouter(schema, context_getter=get_context)