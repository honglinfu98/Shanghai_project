import os
from telethon import TelegramClient
from ftrading.config import TELEGRAM_API_ID, TELEGRAM_API_HASH
from ftrading.setting import PROJECT_ROOT

if TELEGRAM_API_ID is None or TELEGRAM_API_HASH is None:
    raise ValueError("TELEGRAM_API_ID and TELEGRAM_API_HASH must be set in the environment.")
    

client = TelegramClient(
    os.path.join(os.path.join(PROJECT_ROOT, 'data/session'), 'session_name.session'),
    int(TELEGRAM_API_ID),
    str(TELEGRAM_API_HASH)
) 