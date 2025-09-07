# 🔧 Исправление ошибки экспорта CSV

## 📋 Проблема

При попытке экспорта серверов в CSV файл возникала ошибка:
```json
{
  "detail": [
    {
      "type": "int_parsing",
      "loc": ["path", "server_id"],
      "msg": "Input should be a valid integer, unable to parse string as an integer",
      "input": "export.csv"
    }
  ]
}
```

## ❌ Причина проблемы:

### **Конфликт маршрутов FastAPI:**
```python
# Этот маршрут был определен ПОСЛЕ маршрута с параметром
@router.get("/servers/export.csv")  # ❌ Конфликт!
async def export_servers_csv(...):
    ...

# Этот маршрут перехватывал запрос экспорта
@router.get("/servers/{server_id}")  # ❌ "export.csv" интерпретировался как server_id
async def server_detail(request, server_id: int, ...):
    ...
```

### **Порядок маршрутов в FastAPI:**
- FastAPI обрабатывает маршруты **в порядке их определения**
- Маршрут `/servers/{server_id}` был определен **раньше** `/servers/export.csv`
- URL `/servers/export.csv` интерпретировался как `/servers/{server_id}` где `server_id = "export.csv"`
- FastAPI пытался преобразовать `"export.csv"` в `int`, что вызывало ошибку

## ✅ Исправление:

### **Перемещение маршрута экспорта:**
```python
# ✅ Теперь маршрут экспорта определен ПЕРЕД маршрутом с параметром
@router.get("/servers/export.csv")
async def export_servers_csv(db: AsyncSession = Depends(get_db)):
    servers = (await db.execute(select(Server))).scalars().all()
    def gen():
        yield "hostname,ip_address,system_name,owner,is_cluster,tags\n".encode("utf-8")
        for s in servers:
            row = [
                s.hostname or "",
                s.ip_address or "",
                (s.system_name or "").replace(",", " "),
                (s.owner or "").replace(",", " "),
                "true" if s.is_cluster else "false",
                (s.tags or "").replace(",", ";"),
            ]
            yield (",").join(row).encode("utf-8") + b"\n"
    return StreamingResponse(gen(), media_type="text/csv", 
                           headers={"Content-Disposition": "attachment; filename=servers.csv"})

# ✅ Маршрут с параметром теперь определен ПОСЛЕ
@router.get("/servers/{server_id}")
async def server_detail(request: Request, server_id: int, db: AsyncSession = Depends(get_db)):
    ...
```

## 🎯 Результат:

### **До исправления:**
- ❌ **Ошибка парсинга** `"export.csv"` как integer
- ❌ **Конфликт маршрутов** FastAPI
- ❌ **Невозможность экспорта** серверов

### **После исправления:**
- ✅ **Корректная обработка** `/servers/export.csv`
- ✅ **Правильный порядок** маршрутов
- ✅ **Успешный экспорт** серверов в CSV

## 🔧 Технические детали:

### **Правило FastAPI:**
> **Специфичные маршруты должны быть определены ПЕРЕД общими маршрутами с параметрами**

### **Порядок маршрутов:**
```python
# ✅ Правильный порядок:
@router.get("/servers/export.csv")      # Специфичный маршрут
@router.get("/servers/{server_id}")     # Общий маршрут с параметром

# ❌ Неправильный порядок:
@router.get("/servers/{server_id}")     # Общий маршрут перехватывает запрос
@router.get("/servers/export.csv")      # Специфичный маршрут никогда не выполняется
```

### **Обработка URL:**
```
/servers/export.csv
    ↓
FastAPI проверяет маршруты по порядку:
1. /servers/export.csv ✅ НАЙДЕН! (специфичный)
2. /servers/{server_id} (не проверяется)
```

## 📁 Обновленные файлы:
- `app/routers.py` - перемещен маршрут экспорта выше маршрута с параметром

## 🎉 Заключение:

Проблема с экспортом CSV полностью решена:
- **Устранен конфликт** маршрутов FastAPI
- **Установлен правильный порядок** определения маршрутов
- **Восстановлена функциональность** экспорта серверов

**Теперь экспорт серверов работает корректно!** 🚀
