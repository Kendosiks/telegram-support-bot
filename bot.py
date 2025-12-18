import asyncio
import logging
import os
import bcrypt
import aiosqlite
import json
import hmac
import hashlib
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import WebAppInfo, ReplyKeyboardMarkup, KeyboardButton
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
MINI_APP_URL = os.getenv("MINI_APP_URL")
ADMIN_IDS = [int(x.strip()) for x in os.getenv("ADMIN_IDS", "8086087793").split(",") if x.strip()]

logging.basicConfig(level=logging.INFO)

bot = Bot(token=TOKEN)
dp = Dispatcher()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Разрешаем все (для ngrok и Vercel)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "support_bot.db"

async def init_db():
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("CREATE TABLE IF NOT EXISTS admins (user_id INTEGER PRIMARY KEY, password_hash TEXT)")
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
        hashed = bcrypt.hashpw("1234".encode(), bcrypt.gensalt())
        for aid in ADMIN_IDS:
            await db.execute("INSERT OR IGNORE INTO admins (user_id, password_hash) VALUES (?, ?)", (aid, hashed))
        await db.commit()

def validate_init_data(init_data: str):
    try:
        # Парсим параметры (split с =1 для поддержки = в значениях)
        params = {}
        for pair in init_data.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v

        received_hash = params.pop("hash", None)
        if not received_hash:
            raise ValueError("No hash")

        # data_check_string: raw значения, без unquote (Telegram использует raw)
        data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(params.items()))

        # Правильный secret_key: key = "WebAppData", message = TOKEN
        secret_key = hmac.new(b"WebAppData", TOKEN.encode(), hashlib.sha256).digest()

        # calculated_hash
        calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

        print(f"Calculated: {calculated_hash}, Received: {received_hash}")  # Для дебага

        if calculated_hash != received_hash:
            raise ValueError("Hash mismatch")

        # Парсим user
        user_json = params.get("user", "{}")
        return json.loads(user_json)

    except Exception as e:
        print("Validation error:", str(e))
        raise HTTPException(status_code=401, detail="Invalid initData")
        
def get_admin_keyboard():
    button = KeyboardButton(text="Открыть чаты", web_app=WebAppInfo(url=MINI_APP_URL))
    return ReplyKeyboardMarkup(keyboard=[[button]], resize_keyboard=True)

@dp.message(Command("start"))
async def start(message: types.Message):
    if message.from_user.id in ADMIN_IDS:
        await message.answer("Привет, админ! Вот панель чатов:", reply_markup=get_admin_keyboard())
    else:
        await message.answer("Привет, напиши свою проблему и я помогу тебе ее решить!\nЕсли бот молчит — мы уже получили сообщение.")

@dp.message()
async def handle_message(message: types.Message):
    if message.from_user.id in ADMIN_IDS:
        return
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("INSERT INTO messages (user_id, username, text, is_from_user) VALUES (?, ?, ?, 1)",
                         (message.from_user.id, message.from_user.username or "User", message.text))
        await db.commit()

class LoginRequest(BaseModel):
    init_data: str
    password: str

@app.post("/api/login")
async def login(request: LoginRequest):
    user = validate_init_data(request.init_data)
    if user["id"] not in ADMIN_IDS:
        raise HTTPException(status_code=403, detail="Forbidden")
    async with aiosqlite.connect(DB_FILE) as db:
        cursor = await db.execute("SELECT password_hash FROM admins WHERE user_id = ?", (user["id"],))
        row = await cursor.fetchone()
        if row is None:
            # Первый вход — создаём пароль
            hashed = bcrypt.hashpw(request.password.encode(), bcrypt.gensalt())
            await db.execute("INSERT INTO admins (user_id, password_hash) VALUES (?, ?)", (user["id"], hashed))
            await db.commit()
            return {"success": True}
        if bcrypt.checkpw(request.password.encode(), row[0]):
            return {"success": True}
        raise HTTPException(status_code=401, detail="Wrong password")

@app.get("/api/chats")
async def chats(init_data: str = None):
    if not init_data:
        raise HTTPException(status_code=400, detail="No init_data")
    user = validate_init_data(init_data)
    if user["id"] not in ADMIN_IDS:
        raise HTTPException(status_code=403)
    async with aiosqlite.connect(DB_FILE) as db:
        rows = await db.execute_fetchall("SELECT user_id, username, text, is_from_user, timestamp FROM messages ORDER BY timestamp")
        chats = {}
        for row in rows:
            uid = row[0]
            if uid not in chats:
                chats[uid] = {"username": row[1] or "User", "messages": []}
            chats[uid]["messages"].append({"text": row[2], "from_user": row[3], "time": str(row[4])})
        return chats

class SendRequest(BaseModel):
    init_data: str
    to_user_id: int
    text: str

@app.post("/api/send")
async def send(request: SendRequest):
    user = validate_init_data(request.init_data)
    if user["id"] not in ADMIN_IDS:
        raise HTTPException(status_code=403)
    await bot.send_message(request.to_user_id, request.text)
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("INSERT INTO messages (user_id, username, text, is_from_user) VALUES (?, ?, ?, 0)",
                         (request.to_user_id, "Admin", request.text))
        await db.commit()
    return {"success": True}

async def polling_task():
    await init_db()
    await dp.start_polling(bot)

if __name__ == "__main__":
    # Запускаем polling и FastAPI одновременно
    import threading

    # Поток для aiogram polling
    def start_polling():
        asyncio.run(polling_task())

    threading.Thread(target=start_polling, daemon=True).start()

    # Основной поток для FastAPI (uvicorn)
    uvicorn.run(app, host="0.0.0.0", port=8000)
