#!/usr/bin/env python3
"""
Скрипт для тестирования Telegram бота
"""

import os
import asyncio
import httpx
from app.config import settings

async def test_telegram_bot():
    """Тестирование отправки сообщения в Telegram"""
    
    if not settings.telegram_bot_token:
        print("❌ TELEGRAM_BOT_TOKEN не настроен в .env файле")
        return
    
    if not settings.telegram_chat_id:
        print("❌ TELEGRAM_CHAT_ID не настроен в .env файле")
        return
    
    # Тестовое сообщение
    test_message = """
🚨 КРИТИЧЕСКИЙ АЛЕРТ

Сообщение:
Тестовое уведомление от Server Check Monitor

Время: 2024-01-15 14:30:25
Источник: Server Check Monitor
"""
    
    try:
        url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": settings.telegram_chat_id,
            "text": test_message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json=payload)
            
        if response.status_code == 200:
            print("✅ Тестовое сообщение успешно отправлено в Telegram!")
            print(f"📱 Chat ID: {settings.telegram_chat_id}")
            print(f"🤖 Bot Token: {settings.telegram_bot_token[:10]}...")
        else:
            print(f"❌ Ошибка отправки: {response.status_code}")
            print(f"Ответ: {response.text}")
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")

async def test_bot_info():
    """Получение информации о боте"""
    
    if not settings.telegram_bot_token:
        print("❌ TELEGRAM_BOT_TOKEN не настроен")
        return
    
    try:
        url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/getMe"
        
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url)
            
        if response.status_code == 200:
            bot_info = response.json()
            if bot_info.get("ok"):
                bot_data = bot_info["result"]
                print("✅ Информация о боте:")
                print(f"   Имя: {bot_data.get('first_name')}")
                print(f"   Username: @{bot_data.get('username')}")
                print(f"   ID: {bot_data.get('id')}")
                print(f"   Может присоединяться к группам: {bot_data.get('can_join_groups')}")
            else:
                print(f"❌ Ошибка API: {bot_info.get('description')}")
        else:
            print(f"❌ HTTP ошибка: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")

async def main():
    print("🤖 Тестирование Telegram бота для Server Check")
    print("=" * 50)
    
    print("\n1. Проверка информации о боте:")
    await test_bot_info()
    
    print("\n2. Отправка тестового сообщения:")
    await test_telegram_bot()
    
    print("\n" + "=" * 50)
    print("✅ Тестирование завершено!")

if __name__ == "__main__":
    asyncio.run(main())
