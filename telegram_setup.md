# 🤖 Настройка Telegram бота для уведомлений

## 1. Создание бота

1. **Найдите @BotFather в Telegram**
2. **Отправьте команду**: `/newbot`
3. **Введите название**: `Server Check Monitor`
4. **Введите username**: `server_check_monitor_bot`
5. **Сохраните токен**: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`

## 2. Получение Chat ID

### Способ 1: Через @userinfobot
1. Найдите `@userinfobot`
2. Отправьте любое сообщение
3. Получите ваш Chat ID

### Способ 2: Через API
1. Отправьте сообщение вашему боту
2. Откройте: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Найдите `"chat":{"id":123456789}`

## 3. Настройка .env файла

Создайте файл `.env` в корне проекта:

```bash
# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=123456789

# Other settings...
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your-email@gmail.com
SMTP_USE_TLS=true

# Slack (опционально)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
SLACK_CHANNEL=#alerts

# Discord (опционально)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK
```

## 4. Тестирование

После настройки:
1. Перезапустите приложение
2. Создайте тестовый алерт
3. Проверьте получение уведомления в Telegram

## 5. Примеры уведомлений

### Алерт о недоступности сервера
```
🚨 Server Check Alert

Rule 'Порт 80 недоступен' triggered on server 1: reachable != 1 (value=0)

Сервер: web1 (192.168.1.10)
Время: 2024-01-15 14:30:25
```

### Алерт о высокой загрузке CPU
```
⚠️ Server Check Alert

Rule 'Высокая загрузка CPU' triggered on server 2: cpu > 90 (value=95.2)

Сервер: db1 (192.168.1.20)
Время: 2024-01-15 14:35:10
```

## 6. Дополнительные возможности

### Команды бота
Можно добавить команды для управления:
- `/status` - статус всех серверов
- `/alerts` - активные алерты
- `/help` - справка

### Групповые чаты
Для отправки в группу:
1. Добавьте бота в группу
2. Сделайте бота администратором
3. Используйте Chat ID группы

## 7. Безопасность

- Никогда не публикуйте токен бота
- Используйте переменные окружения
- Регулярно обновляйте токены
- Ограничьте доступ к боту
