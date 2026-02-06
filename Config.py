import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///safety_helmet.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'jwt-secret-key-change-this'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # Risk thresholds
    GAS_THRESHOLD = 2700
    TEMP_THRESHOLD = 40
    RISK_SAFE = 30
    RISK_WARNING = 60
    RISK_DANGER = 100
    
    # Telegram Bot Config
    TELEGRAM_BOT_TOKEN = 'YOUR_BOT_TOKEN'  # Create via @BotFather
    MANAGER_CHAT_ID = 'MANAGER_CHAT_ID'    # Get via @userinfobot
