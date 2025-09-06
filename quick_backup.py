#!/usr/bin/env python3
"""
Быстрый backup приложения Server Check
Создает минимальный backup только с важными файлами
"""

import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

def quick_backup():
    """Создание быстрого backup'а"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"quick_backup_{timestamp}"
    backup_file = f"backups/{backup_name}.zip"
    
    # Создаем директорию backups если её нет
    os.makedirs("backups", exist_ok=True)
    
    print(f"🚀 Создание быстрого backup: {backup_name}")
    print("=" * 50)
    
    # Важные файлы для backup'а
    important_files = [
        "app/",
        "templates/",
        "static/",
        "requirements.txt",
        "alembic.ini",
        "server_check.db",
        ".env",
        "README.md"
    ]
    
    try:
        with zipfile.ZipFile(backup_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for item in important_files:
                if os.path.exists(item):
                    if os.path.isdir(item):
                        for root, dirs, files in os.walk(item):
                            for file in files:
                                file_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_path)
                                zipf.write(file_path, arcname)
                        print(f"   ✓ Директория: {item}")
                    else:
                        zipf.write(item, item)
                        print(f"   ✓ Файл: {item}")
                else:
                    print(f"   ⚠️ Не найден: {item}")
        
        # Получаем размер файла
        size = os.path.getsize(backup_file)
        size_mb = size / (1024 * 1024)
        
        print("✅ Быстрый backup создан!")
        print(f"📁 Файл: {backup_file}")
        print(f"📊 Размер: {size_mb:.2f} MB")
        
        return backup_file
        
    except Exception as e:
        print(f"❌ Ошибка создания backup: {e}")
        return None

if __name__ == "__main__":
    quick_backup()
