# 💾 Руководство по Backup приложения Server Check

## 📋 Обзор

Система backup'а включает несколько инструментов для создания резервных копий вашего приложения:

- **`backup.py`** - Полный backup с восстановлением
- **`auto_backup.py`** - Автоматический backup по расписанию
- **`quick_backup.py`** - Быстрый backup важных файлов

## 🚀 Быстрый старт

### 1. Создание backup'а

```bash
# Полный backup
python backup.py create

# Быстрый backup
python quick_backup.py

# Автоматический backup один раз
python auto_backup.py once
```

### 2. Просмотр backup'ов

```bash
python backup.py list
```

### 3. Восстановление

```bash
python backup.py restore server_check_backup_20240115_143025.zip
```

## 📁 Структура backup'а

### Полный backup включает:
- ✅ Исходный код приложения (`app/`, `templates/`, `static/`)
- ✅ База данных SQLite (`server_check.db`)
- ✅ SQL dump базы данных (`database_dump.sql`)
- ✅ Конфигурационные файлы (`.env`, `alembic.ini`)
- ✅ Документация (`README.md`, `*.md`)
- ✅ Миграции Alembic (`alembic/`)
- ✅ Зависимости (`requirements.txt`)

### Быстрый backup включает:
- ✅ Основные директории (`app/`, `templates/`, `static/`)
- ✅ База данных (`server_check.db`)
- ✅ Конфигурация (`.env`, `requirements.txt`)
- ✅ Документация (`README.md`)

## ⚙️ Настройка автоматического backup'а

### 1. Установка зависимостей

```bash
pip install schedule
```

### 2. Запуск планировщика

```bash
# В фоне
nohup python auto_backup.py schedule > backup.log 2>&1 &

# Или в screen/tmux
screen -S backup
python auto_backup.py schedule
```

### 3. Расписание по умолчанию

- **Ежедневно в 02:00** - Создание backup'а
- **По воскресеньям в 03:00** - Очистка старых backup'ов (старше 30 дней)

## 🔧 Настройка cron (Linux/macOS)

### 1. Открыть crontab

```bash
crontab -e
```

### 2. Добавить задачи

```bash
# Ежедневный backup в 2:00
0 2 * * * cd /path/to/server_check && python backup.py create

# Еженедельная очистка в воскресенье в 3:00
0 3 * * 0 cd /path/to/server_check && python auto_backup.py cleanup
```

## 📊 Мониторинг backup'ов

### 1. Проверка логов

```bash
# Просмотр логов автоматического backup'а
tail -f backup.log

# Просмотр последних backup'ов
python backup.py list
```

### 2. Проверка размера backup'ов

```bash
# Размер директории backups
du -sh backups/

# Размер отдельных backup'ов
ls -lh backups/
```

## 🚨 Восстановление после сбоя

### 1. Полное восстановление

```bash
# Остановить приложение
pkill -f uvicorn

# Восстановить из backup'а
python backup.py restore server_check_backup_20240115_143025.zip

# Установить зависимости
pip install -r requirements.txt

# Запустить приложение
uvicorn app.main:app --reload --port 8000
```

### 2. Восстановление только базы данных

```bash
# Остановить приложение
pkill -f uvicorn

# Восстановить базу данных
cp backups/server_check_backup_20240115_143025/server_check.db ./

# Запустить приложение
uvicorn app.main:app --reload --port 8000
```

## 🔐 Безопасность backup'ов

### 1. Шифрование backup'ов

```bash
# Создание зашифрованного backup'а
gpg --symmetric --cipher-algo AES256 backups/server_check_backup_20240115_143025.zip

# Расшифровка
gpg --decrypt backups/server_check_backup_20240115_143025.zip.gpg > backup.zip
```

### 2. Резервное копирование в облако

```bash
# Загрузка в AWS S3
aws s3 cp backups/ s3://your-bucket/server-check-backups/ --recursive

# Загрузка в Google Cloud
gsutil -m cp -r backups/ gs://your-bucket/server-check-backups/
```

## 📈 Оптимизация backup'ов

### 1. Исключение ненужных файлов

Создайте файл `.backupignore`:

```
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
env/
venv/
.venv/
.git/
*.log
temp/
tmp/
```

### 2. Сжатие backup'ов

```bash
# Максимальное сжатие
python backup.py create --compress-level 9
```

## 🛠️ Устранение неполадок

### Проблема: "База данных заблокирована"

**Решение:**
```bash
# Остановить приложение перед backup'ом
pkill -f uvicorn
python backup.py create
uvicorn app.main:app --reload --port 8000
```

### Проблема: "Недостаточно места на диске"

**Решение:**
```bash
# Очистить старые backup'ы
python auto_backup.py cleanup

# Проверить свободное место
df -h
```

### Проблема: "Ошибка восстановления"

**Решение:**
```bash
# Проверить целостность backup'а
unzip -t backups/server_check_backup_20240115_143025.zip

# Восстановить пошагово
python backup.py restore server_check_backup_20240115_143025.zip --verbose
```

## 📋 Чек-лист backup'а

- [ ] Регулярные backup'ы настроены
- [ ] Backup'ы тестируются на восстановление
- [ ] Старые backup'ы автоматически удаляются
- [ ] Backup'ы хранятся в безопасном месте
- [ ] Документация по восстановлению готова
- [ ] Мониторинг backup'ов настроен

## 🎯 Рекомендации

1. **Частота backup'ов**: Ежедневно для продакшена
2. **Хранение**: Минимум 30 дней, лучше 90 дней
3. **Тестирование**: Ежемесячно тестируйте восстановление
4. **Мониторинг**: Настройте алерты на неудачные backup'ы
5. **Безопасность**: Шифруйте backup'ы с чувствительными данными

## 📞 Поддержка

При возникновении проблем с backup'ом:

1. Проверьте логи: `tail -f backup.log`
2. Убедитесь в наличии свободного места
3. Проверьте права доступа к файлам
4. Обратитесь к документации по восстановлению
