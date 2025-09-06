#!/usr/bin/env python3
"""
Автоматический backup приложения Server Check
Запускается по расписанию или вручную
"""

import os
import schedule
import time
from datetime import datetime
from backup import ServerCheckBackup

class AutoBackup:
    def __init__(self):
        self.backup = ServerCheckBackup()
        self.log_file = "backup.log"
    
    def log(self, message):
        """Логирование сообщений"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        print(log_message)
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_message + "\n")
    
    def create_scheduled_backup(self):
        """Создание backup по расписанию"""
        try:
            self.log("🔄 Начало автоматического backup'а")
            success = self.backup.create_backup()
            
            if success:
                self.log("✅ Автоматический backup завершен успешно")
            else:
                self.log("❌ Ошибка автоматического backup'а")
                
        except Exception as e:
            self.log(f"❌ Критическая ошибка backup'а: {e}")
    
    def cleanup_old_backups(self, keep_days=30):
        """Очистка старых backup'ов"""
        try:
            from pathlib import Path
            import os
            
            backup_dir = Path("backups")
            if not backup_dir.exists():
                return
            
            cutoff_time = time.time() - (keep_days * 24 * 60 * 60)
            deleted_count = 0
            
            for backup_file in backup_dir.glob("*.zip"):
                if backup_file.stat().st_mtime < cutoff_time:
                    backup_file.unlink()
                    deleted_count += 1
                    self.log(f"🗑️ Удален старый backup: {backup_file.name}")
            
            if deleted_count > 0:
                self.log(f"🧹 Удалено {deleted_count} старых backup'ов")
                
        except Exception as e:
            self.log(f"❌ Ошибка очистки старых backup'ов: {e}")
    
    def start_scheduler(self):
        """Запуск планировщика backup'ов"""
        self.log("🚀 Запуск планировщика backup'ов")
        
        # Ежедневный backup в 2:00
        schedule.every().day.at("02:00").do(self.create_scheduled_backup)
        
        # Еженедельная очистка старых backup'ов в воскресенье в 3:00
        schedule.every().sunday.at("03:00").do(self.cleanup_old_backups)
        
        # Тестовый backup каждые 5 минут (для демонстрации)
        # schedule.every(5).minutes.do(self.create_scheduled_backup)
        
        self.log("📅 Планировщик настроен:")
        self.log("   - Ежедневный backup в 02:00")
        self.log("   - Очистка старых backup'ов по воскресеньям в 03:00")
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # Проверяем каждую минуту
    
    def run_once(self):
        """Запуск backup'а один раз"""
        self.log("🔄 Запуск разового backup'а")
        self.create_scheduled_backup()
        self.cleanup_old_backups()

def main():
    """Главная функция"""
    import sys
    
    auto_backup = AutoBackup()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "once":
            auto_backup.run_once()
        elif command == "schedule":
            auto_backup.start_scheduler()
        elif command == "cleanup":
            auto_backup.cleanup_old_backups()
        else:
            print("❌ Неизвестная команда")
            print_help()
    else:
        print_help()

def print_help():
    """Вывод справки"""
    print("🤖 Server Check Auto Backup")
    print("=" * 50)
    print("Использование:")
    print("  python auto_backup.py once      - Создать backup один раз")
    print("  python auto_backup.py schedule  - Запустить планировщик")
    print("  python auto_backup.py cleanup   - Очистить старые backup'ы")
    print()
    print("Примеры:")
    print("  python auto_backup.py once")
    print("  python auto_backup.py schedule")
    print()
    print("Для запуска в фоне:")
    print("  nohup python auto_backup.py schedule > backup.log 2>&1 &")

if __name__ == "__main__":
    main()
