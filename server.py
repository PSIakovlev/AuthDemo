import hmac
import hashlib
import base64
import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "e46acb763e9180d6e49f9af3e1eb87a64a3b3d416166995fce14d4723da88d0c"
PASSWORD_SALT = "b8c19d27325c39c5b0aca28948f7cb21f85455b050bc4990f9f3d659ac4575d7"


hash_password = hashlib.sha256(("some_password_1" + PASSWORD_SALT).encode())
print(hash_password.hexdigest())


def sign_data(data: str) -> str:
    """Возвращает подписанные данные datq"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(user_name: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[user_name]["password"].lower()
    return password_hash == stored_password_hash


users = {
    "alex@user.com": {
        "name": "Алексей",
        "password": "88ac5122a17533eb12f9589db1be66b63d1152d7e7b004f2f66799f2b63cb24f",
        "balance": 100_000
    },
    "ivan@user.com": {
        "name": "Иван",
        "password": "77cc6f1c3f1ee8f5bd39337e6c7938595b4ef5869f74a14ebc00d1ae18024e7e",
        "balance": 123_456
    }
}


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templaces/login.html', 'r', encoding='utf-8') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        responce = Response(login_page, media_type="text/html")
        responce.delete_cookie(key="username")
        return responce

    try:
        user = users[valid_username]
    except KeyError:
        responce = Response(login_page, media_type="text/html")
        responce.delete_cookie(key="username")
        return responce
    return Response(f"Привет, {users[valid_username]['name']}!<br />"
                    f"Баланс: {users[valid_username]['balance']}",
                    media_type="text/html")


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я Вас не знаю!"
            }),
            media_type="application/json")

    responce = Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}"
        }),
        media_type='application/json')

    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    responce.set_cookie(key="username", value=username_signed)
    return responce
