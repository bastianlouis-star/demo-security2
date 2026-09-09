import base64
import pickle
from typing import Annotated

from fastapi import APIRouter, Body, Depends
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from dto.register_dto import RegisterDTO
from models.account import Account
from models.db import get_db
from utils import jwt_utils, password_utils

router = APIRouter(prefix='/auth')

@router.post('/register', status_code=201)
async def register(
    dto: Annotated[RegisterDTO, Body()], 
    session: Annotated[Session, Depends(get_db)]
):
    try: 
        account = Account(
            username=dto.username,
            email=dto.email,
            password_hash=password_utils.hash(dto.password),
            role=dto.role
        )
        session.add(account)
        session.flush()
    except:
        raise HTTPException(status_code=400, detail='Impossible de sauver cet account (vérifier vos données)')

@router.post('/login')
def login(
    # permet de récupérer les donnnées du formulaire
    dto: Annotated[OAuth2PasswordRequestForm, Depends()], 
    session: Annotated[Session, Depends(get_db)]
):
    account = session.execute(
        select(Account).where(Account.username == dto.username)
    ).scalar()

    if not account or not password_utils.verify_password(
        dto.password, account.password_hash
    ):
        raise HTTPException(401)

    return {
        'access_token': jwt_utils.create_token(account.id, account.role)
    }

@router.get('/need_authentication')
def need_authentication(
    # parametre a ajouter sur les routes qui ont besoins d'une authentification
    claims: Annotated[dict|None, Depends(jwt_utils.verify_token)]
):
    return claims

@router.get('/need_role_admin')
def need_role_admin(
    # parametre a ajouter sur les routes qui ont besoins d'une authentification
    claims: Annotated[dict|None, Depends(jwt_utils.RoleGuard(['admin']))]
):
    return claims


@router.post("/session/restore")
def restore_session(payload: str):
    try:
    # ❌ DANGEREUX : Désérialisation directe d'octets fournis par le client !
        raw_data = base64.b64decode(payload)
        session_data = pickle.loads(raw_data) # 💥 RCE immédiat ici !
        return {"status": "session restaurée", "data": str(session_data)}
    except Exception:
        raise HTTPException(status_code=400, detail="Payload invalide")
