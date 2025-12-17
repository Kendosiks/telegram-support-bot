import asyncio
import logging
import os
import bcrypt
import aiosqlite
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import WebAppInfo, ReplyKeyboardMarkup, KeyboardButton
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import hmac
import hashlib
import base64
import json
import time

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
MINI_APP_URL = os.getenv("MINI_APP_URL")
ADMIN_IDS = [int(id) for id in os.getenv("ADMIN_IDS", "").split(",") if id]
SECRET_KEY = os.getenv("SECRET_KEY")

logging.basicConfig(level=logging.INFO)

bot = Bot(token=TOKEN)
dp = Dispatcher()
app = FastAPI()  # API для Mini App

DB_FILE = "support_bot.db"

# CORS для Mini App (разрешаем запросы с Vercel)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене укажи домен Vercel
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def init_db():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                user_id INTEGER PRIMARY KEY,
                password_hash TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                text TEXT,
                is_from_user BOOLEAN,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Добавляем первого админа с паролем 1234, если нет
        hashed = bcrypt.hashpw("1234".encode(), bcrypt.gensalt())
        await db.execute("INSERT OR IGNORE INTO admins (user_id, password_hash) VALUES (?, ?)", (ADMIN_IDS[0], hashed))
        await db.commit()

# Клавиатура для админа
def get_admin_keyboard():
    button = KeyboardButton(text="Открыть чаты", web_app=WebAppInfo(url=MINI_APP_URL))
    return ReplyKeyboardMarkup(keyboard=[[button]], resize_keyboard=True)

@dp.message(Command("start"))
async def start(message: types.Message):
    if message.from_user.id in ADMIN_IDS:
        await message.answer("Привет, админ! Вот панель чатов:", reply_markup=get_admin_keyboard())
    else:
        await message.answer(
            "Привет, напиши свою проблему и я помогу тебе ее решить! "
            "Если вам бот ничего не ответил после написания вашей проблемы, то не паникуйте, "
            "администрация получила ваше сообщение, так же можете и дальше их отправлять."
        )

@dp.message()
async def handle_message(message: types.Message):
    user_id = message.from_user.id
    if user_id in ADMIN_IDS:
        return  # Игнорируем сообщения админов в боте
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO messages (user_id, username, text, is_from_user) VALUES (?, ?, ?, 1)",
            (user_id, message.from_user.username or message.from_user.full_name, message.text)
        )
        await db.commit()
    # Бот молчит

# Валидация initData от Telegram
def validate_init_data(init_data: str) -> dict:
    parsed_data = dict(pair.split('=') for pair in init_data.split('&') if '=' in pair)
    token = parsed_data.pop('hash', None)
    data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(parsed_data.items()))
    secret = hmac.new(b"WebAppData", TOKEN.encode(), hashlib.sha256).digest()
    calculated_hash = hmac.new(secret, data_check_string.encode(), hashlib.sha256).hexdigest()
    if calculated_hash != token:
        raise HTTPException(status_code=401, detail="Invalid initData")
    user = json.loads(parsed_data['user'])
    return user

class LoginBody(BaseModel):
    init_data: str
    password: str

@app.post("/api/login")
async def login(body: LoginBody):
    user = validate_init_data(body.init_data)
    if user['id'] not in ADMIN_IDS:
        raise HTTPException(status_code=403, detail="Not admin")
    async with aiosqlite.connect(DB_FILE) as db:
        row = await db.execute_fetchall("SELECT password_hash FROM admins WHERE user_id = ?", (user['id'],))
        if not row:
            # Создаём пароль, если первый раз
            hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt())
            await db.execute("INSERT INTO admins (user_id, password_hash) VALUES (?, ?)", (user['id'], hashed))
            await db.commit()
            return {"success": True, "message": "Пароль создан"}
        else:
            if bcrypt.checkpw(body.password.encode(), row[0][0]):
                return {"success": True}
            raise HTTPException(status_code=401, detail="Wrong password")

@app.get("/api/chats")
async def get_chats(request: Request):
    init_data = request.headers.get("init-data")
    if not init_data:
        raise HTTPException(status_code=400, detail="Missing init_data")
    user = validate_init_data(init_data)
    if user['id'] not in ADMIN_IDS:
        raise HTTPException(status_code=403, detail="Not admin")
    async with aiosqlite.connect(DB_FILE) as db:
        # Получаем уникальных пользователей
        users = await db.execute_fetchall("SELECT DISTINCT user_id, username FROM messages GROUP BY user_id")
        chats = {}
        for u_id, username in users:
            msgs = await db.execute_fetchall(
                "SELECT text, is_from_user, timestamp FROM messages WHERE user_id = ? ORDER BY timestamp",
                (u_id,)
            )
            chats[u_id] = {"username": username, "messages": [{"text": m[0], "from_user": bool(m[1]), "time": m[2]} for m in msgs]}
        return chats

class SendBody(BaseModel):
    init_data: str
    to_user_id: int
    text: str

@app.post("/api/send")
async def send_message(body: SendBody):
    user = validate_init_data(body.init_data)
    if user['id'] not in ADMIN_IDS:
        raise HTTPException(status_code=403, detail="Not admin")
    await bot.send_message(body.to_user_id, body.text)
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO messages (user_id, username, text, is_from_user) VALUES (?, ?, ?, 0)",
            (body.to_user_id, "Admin", body.text)
        )
        await db.commit()
    return {"success": True}

async def main():
    await init_db()
    # Запускаем бота
    asyncio.create_task(dp.start_polling(bot))
    # FastAPI запускается отдельно (uvicorn)

if __name__ == "__main__":
    asyncio.run(main())