#!/usr/bin/env python3
"""
Скрипт для создания backup приложения Server Check
"""

import os
import shutil
import sqlite3
import json
import zipfile
from datetime import datetime
from pathlib import Path
import subprocess
import sys

class ServerCheckBackup:
    def __init__(self, backup_dir="backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.backup_name = f"server_check_backup_{self.timestamp}"
        self.backup_path = self.backup_dir / self.backup_name
        
    def create_backup(self):
        """Создание полного backup приложения"""
        print(f"🚀 Создание backup: {self.backup_name}")
        print("=" * 50)
        
        try:
            # Создаем директорию для backup
            self.backup_path.mkdir(exist_ok=True)
            
            # 1. Копируем исходный код
            print("📁 Копирование исходного кода...")
            self._copy_source_code()
            
            # 2. Создаем backup базы данных
            print("🗄️ Создание backup базы данных...")
            self._backup_database()
            
            # 3. Копируем конфигурационные файлы
            print("⚙️ Копирование конфигурации...")
            self._copy_config_files()
            
            # 4. Создаем архив
            print("📦 Создание архива...")
            self._create_archive()
            
            # 5. Очищаем временные файлы
            print("🧹 Очистка временных файлов...")
            self._cleanup()
            
            print("✅ Backup успешно создан!")
            print(f"📁 Путь: {self.backup_path}.zip")
            print(f"📊 Размер: {self._get_file_size(self.backup_path.with_suffix('.zip'))}")
            
        except Exception as e:
            print(f"❌ Ошибка создания backup: {e}")
            self._cleanup()
            return False
            
        return True
    
    def _copy_source_code(self):
        """Копирование исходного кода приложения"""
        source_files = [
            "app/",
            "templates/",
            "static/",
            "alembic/",
            "requirements.txt",
            "alembic.ini",
            "README.md",
            "CSRF_SETUP.md",
            "IMMEDIATE_IMPROVEMENTS.md",
            "MONITORING_SETUP.md",
            "telegram_setup.md"
        ]
        
        for item in source_files:
            if os.path.exists(item):
                if os.path.isdir(item):
                    shutil.copytree(item, self.backup_path / item)
                else:
                    shutil.copy2(item, self.backup_path / item)
                print(f"   ✓ {item}")
    
    def _backup_database(self):
        """Создание backup базы данных SQLite"""
        db_file = "server_check.db"
        if os.path.exists(db_file):
            # Создаем SQL dump
            dump_file = self.backup_path / "database_dump.sql"
            self._create_sql_dump(db_file, dump_file)
            
            # Копируем файл базы данных
            shutil.copy2(db_file, self.backup_path / db_file)
            print(f"   ✓ {db_file}")
            print(f"   ✓ database_dump.sql")
        else:
            print("   ⚠️ База данных не найдена")
    
    def _create_sql_dump(self, db_file, dump_file):
        """Создание SQL dump базы данных"""
        try:
            conn = sqlite3.connect(db_file)
            with open(dump_file, 'w', encoding='utf-8') as f:
                for line in conn.iterdump():
                    f.write(f"{line}\n")
            conn.close()
        except Exception as e:
            print(f"   ⚠️ Ошибка создания SQL dump: {e}")
    
    def _copy_config_files(self):
        """Копирование конфигурационных файлов"""
        config_files = [
            ".env",
            ".env.example",
            "config.py",
            "alembic.ini"
        ]
        
        for config_file in config_files:
            if os.path.exists(config_file):
                shutil.copy2(config_file, self.backup_path / config_file)
                print(f"   ✓ {config_file}")
    
    def _create_archive(self):
        """Создание ZIP архива"""
        archive_path = self.backup_path.with_suffix('.zip')
        
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.backup_path):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(self.backup_path)
                    zipf.write(file_path, arcname)
        
        print(f"   ✓ Архив создан: {archive_path.name}")
    
    def _cleanup(self):
        """Очистка временных файлов"""
        if self.backup_path.exists():
            shutil.rmtree(self.backup_path)
    
    def _get_file_size(self, file_path):
        """Получение размера файла в читаемом формате"""
        size = os.path.getsize(file_path)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def list_backups(self):
        """Список существующих backup'ов"""
        print("📋 Существующие backup'ы:")
        print("=" * 50)
        
        if not self.backup_dir.exists():
            print("   Нет backup'ов")
            return
        
        backups = []
        for file in self.backup_dir.glob("*.zip"):
            stat = file.stat()
            backups.append({
                'name': file.name,
                'size': self._get_file_size(file),
                'date': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            })
        
        if not backups:
            print("   Нет backup'ов")
            return
        
        # Сортируем по дате (новые сверху)
        backups.sort(key=lambda x: x['date'], reverse=True)
        
        for i, backup in enumerate(backups, 1):
            print(f"   {i}. {backup['name']}")
            print(f"      📅 {backup['date']}")
            print(f"      📊 {backup['size']}")
            print()
    
    def restore_backup(self, backup_name):
        """Восстановление из backup'а"""
        backup_file = self.backup_dir / backup_name
        
        if not backup_file.exists():
            print(f"❌ Backup файл не найден: {backup_name}")
            return False
        
        print(f"🔄 Восстановление из backup: {backup_name}")
        print("=" * 50)
        
        try:
            # Создаем временную директорию для извлечения
            temp_dir = Path("temp_restore")
            temp_dir.mkdir(exist_ok=True)
            
            # Извлекаем архив
            with zipfile.ZipFile(backup_file, 'r') as zipf:
                zipf.extractall(temp_dir)
            
            # Восстанавливаем файлы
            self._restore_files(temp_dir)
            
            # Очищаем временные файлы
            shutil.rmtree(temp_dir)
            
            print("✅ Восстановление завершено!")
            return True
            
        except Exception as e:
            print(f"❌ Ошибка восстановления: {e}")
            return False
    
    def _restore_files(self, temp_dir):
        """Восстановление файлов из временной директории"""
        # Восстанавливаем исходный код
        for item in temp_dir.iterdir():
            if item.is_dir():
                if item.name in ["app", "templates", "static", "alembic"]:
                    if os.path.exists(item.name):
                        shutil.rmtree(item.name)
                    shutil.copytree(item, item.name)
                    print(f"   ✓ Восстановлена директория: {item.name}")
            else:
                if item.name in ["requirements.txt", "alembic.ini", "README.md"]:
                    shutil.copy2(item, item.name)
                    print(f"   ✓ Восстановлен файл: {item.name}")
        
        # Восстанавливаем базу данных
        db_file = temp_dir / "server_check.db"
        if db_file.exists():
            shutil.copy2(db_file, "server_check.db")
            print("   ✓ Восстановлена база данных")
        
        # Восстанавливаем конфигурацию
        config_files = [".env", "config.py"]
        for config_file in config_files:
            config_path = temp_dir / config_file
            if config_path.exists():
                shutil.copy2(config_path, config_file)
                print(f"   ✓ Восстановлен конфиг: {config_file}")

def main():
    """Главная функция"""
    backup = ServerCheckBackup()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "create":
            backup.create_backup()
        elif command == "list":
            backup.list_backups()
        elif command == "restore" and len(sys.argv) > 2:
            backup_name = sys.argv[2]
            backup.restore_backup(backup_name)
        else:
            print("❌ Неизвестная команда")
            print_help()
    else:
        print_help()

def print_help():
    """Вывод справки"""
    print("🔧 Server Check Backup Tool")
    print("=" * 50)
    print("Использование:")
    print("  python backup.py create     - Создать backup")
    print("  python backup.py list       - Список backup'ов")
    print("  python backup.py restore <name> - Восстановить из backup'а")
    print()
    print("Примеры:")
    print("  python backup.py create")
    print("  python backup.py list")
    print("  python backup.py restore server_check_backup_20240115_143025.zip")

if __name__ == "__main__":
    main()
