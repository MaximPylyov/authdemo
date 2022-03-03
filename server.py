import base64
import hashlib
import hmac
import json
from typing import Optional
from urllib import response

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "8d04812c016a2bc3debccae8ef848a66b5c31d0c637ae725c04775b0d77da5d6"
PASSWORD_SALT = "0fdcfe9e7a2db949c81b848dcd76c7d7967bfc92c28ac04e78944390b24bf3d5"

users = {
    "alexey@user.com": {
        "name": "Алексей",
        "password": "0d418199fe4c6516e9fe90652c9bf65191ad5ae1a77de1f2359bf7afdd8c22f4",
        "balance": 100_000
    },
    "petr@user.com": {
        "name": "Пётр",
        "password": "'7d2b71929d064e74a905fcc3d06e3a29f332dcb20b88f9c85ac2054eda986b7f",
        "balance": 555_555
    }
}

def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    """Возвращает логин из подписанной строки в cookie """
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    """Верифицирует пароль"""
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return   password_hash == stored_password_hash

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    """Отрисовка/работа стартовой страницы при открытии"""

    with open("templates/login.html", 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_usename = get_username_from_signed_string(username)
    if not valid_usename:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    
    try:
        user = users[valid_usename]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет, {users[valid_usename]['name']}!<br />"
        f"Баланс: , {users[valid_usename]['balance']}", media_type="text/html")
    

@app.post("/login")
def process_login_page(data: dict = Body(...)):
    """Процесс аунтификации"""
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or  not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю!"
            }),
            media_type='application/json')
    
    response = Response(
        json.dumps({
                "success": True,
                "message": f"Привет, {user['name']} </br>Баланс: {user['balance']} "
        }),
        media_type='application/json')
    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response

