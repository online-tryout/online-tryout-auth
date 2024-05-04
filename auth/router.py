from fastapi import APIRouter, Depends, HTTPException, Response, Cookie
from sqlalchemy.orm import Session

from database import get_db
from auth import schemas, crud, utils

from typing import Annotated
import base64
import json
import uuid
import jwt
import datetime

router = APIRouter()

@router.post("/register")
async def register(user: schemas.UserCreate, token: Annotated[str | None, Cookie()] = None, db: Session = Depends(get_db)):
    if (user.role == 2) and not token:
        raise HTTPException(status_code=401, detail="token not found")
    
    if (user.role == 2) and token:
        try:
            token_data = utils.jwt_decrypt(token)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="token expired")
        
        role = token_data.get("role")
        if role != 2:
            raise HTTPException(status_code=403, detail="unauthorized")

    encoded_password = user.password
    decoded_password = base64.b64decode(encoded_password.encode("ascii")).decode("ascii")
    hashed_password = utils.hash_password(decoded_password)
    user.password = hashed_password

    try:
        crud.create_user(db, user)  
        return {"message": "user registered successfully"}
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    
@router.post("/role")
async def create_role(role: schemas.UserRoleCreate, token: Annotated[str | None, Cookie()] = None, db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="token not found")
    
    token_data = utils.jwt_decrypt(token)
    role_id = token_data.get("role")
    if role_id != 2:
        raise HTTPException(status_code=403, detail="unauthorized")
    
    try:
        crud.create_user_role(db, role)
        return {"message": "role created successfully"}
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

@router.post("/login")
async def login(data: dict, response: Response, db: Session = Depends(get_db)):
    encoded_password = data.get("password")
    decoded_password = base64.b64decode(encoded_password.encode("ascii")).decode("ascii")
    hashed_password = utils.hash_password(decoded_password)

    user = crud.get_user_by_username(db, data.get("username"))
    if (not user) or (user.password != hashed_password):
        raise HTTPException(status_code=401, detail="invalid credentials")
    
    exp =  datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1)
    
    payload_info = {
        "id": str(user.id),
        "username": str(user.username),
        "role": user.role,
        "exp": exp
    }

    response.set_cookie(key = "token", value = utils.jwt_encrypt(payload_info))
    return {"message": "login successful"}

@router.post("/update_info")
async def update_info(data: dict, token: Annotated[str | None, Cookie()] = None, db: Session = Depends(get_db)):
    if "id" in data:
        raise HTTPException(status_code=403, detail="id cannot be updated")
    
    if "role" in data:
        raise HTTPException(status_code=403, detail="role cannot be changed")
    
    if not token:
        raise HTTPException(status_code=401, detail="token not found")
    
    try:
        token_data = utils.jwt_decrypt(token)
        user_id = token_data.get("id")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")

    try:
        crud.update_user(db, user_id, data)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"message": "user updated successfully"}

@router.post("/role/{id}")
async def update_role(id: int, data: dict, token: Annotated[str | None, Cookie()] = None, db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="token not found")
    
    try:
        token_data = utils.jwt_decrypt(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    
    role = token_data.get("role")
    if role != 2:
        raise HTTPException(status_code=403, detail="unauthorized")
    
    try:
        crud.update_role(db, id, data)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"message": "role updated successfully"}

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("token")
    return {"message": "success"}

@router.post("/delete_user")
async def delete_user(response: Response, token: Annotated[str | None, Cookie()] = None, db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="token not found")

    try:
        token_data = utils.jwt_decrypt(token)
        user_id = token_data.get("id")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")

    try:
        crud.delete_user(db, user_id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
    response.delete_cookie("token")
    return {"message": "user deleted successfully"}

@router.post("/delete_user/{id}")
async def delete_user_for_admin(id: uuid.UUID, token: Annotated[str | None, Cookie()] = None, db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="token not found")
    
    try:
        token_data = utils.jwt_decrypt(token)
        role = token_data.get("role")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")

    if role != 2:
        raise HTTPException(status_code=403, detail="unauthorized")
    
    try:
        crud.delete_user(db, id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    
    return {"message": "user deleted successfully"}

@router.post("/role/{id}/delete")
async def delete_role(id: int, token: Annotated[str | None, Cookie()] = None, db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="token not found")
    
    try:
        token_data = utils.jwt_decrypt(token)
        role = token_data.get("role")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")

    if role != 2:
        raise HTTPException(status_code=403, detail="unauthorized")
    
    try:
        crud.delete_user_role(db, id)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"message": "role deleted successfully"}