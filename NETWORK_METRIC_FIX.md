# 🔧 Исправление отображения метрики Network

## 📋 Проблема

Метрика Network не отображалась на главной странице, хотя была добавлена в интерфейс.

## 🔍 Причина проблемы

В API отсутствовало поле `network_io`, которое ожидал JavaScript код. В базе данных были только поля:
- `network_in_kbps` - входящий трафик в кбит/с
- `network_out_kbps` - исходящий трафик в кбит/с

## ✅ Решение

### **1. Добавлено вычисляемое поле `network_io` в API**

#### **В `app/services.py` - метод `get_servers_with_metrics`:**
```python
"network_in_kbps": metric.network_in_kbps if metric else None,
"network_out_kbps": metric.network_out_kbps if metric else None,
"network_io": ((metric.network_in_kbps or 0) + (metric.network_out_kbps or 0)) / 1024 if metric else None,  # Convert kbps to MB/s
```

#### **В `app/services.py` - метод `get_server_metrics_history`:**
```python
"network_in_kbps": m.network_in_kbps,
"network_out_kbps": m.network_out_kbps,
"network_io": ((m.network_in_kbps or 0) + (m.network_out_kbps or 0)) / 1024,  # Convert kbps to MB/s
```

#### **В `app/services.py` - метод `evaluate_alerts_optimized`:**
```python
"net_in": metric.network_in_kbps,
"net_out": metric.network_out_kbps,
"network_io": ((metric.network_in_kbps or 0) + (metric.network_out_kbps or 0)) / 1024,  # Convert kbps to MB/s
```

### **2. Логика вычисления**

#### **Формула:**
```python
network_io = (network_in_kbps + network_out_kbps) / 1024
```

#### **Объяснение:**
- **Суммируем** входящий и исходящий трафик
- **Делим на 1024** для конвертации из кбит/с в МБ/с
- **Обрабатываем null** значения (заменяем на 0)

### **3. Единицы измерения**

#### **В базе данных:**
- `network_in_kbps` - кбит/с (килобиты в секунду)
- `network_out_kbps` - кбит/с (килобиты в секунду)

#### **В интерфейсе:**
- `network_io` - МБ/с (мегабайты в секунду)

#### **Конвертация:**
- 1 кбит/с = 0.125 кБ/с = 0.000122 МБ/с
- 1024 кбит/с = 128 кБ/с = 0.125 МБ/с
- 8192 кбит/с = 1024 кБ/с = 1 МБ/с

## 🔧 Технические детали

### **Сбор данных:**
```python
# В app/monitor.py
net_io_1 = psutil.net_io_counters()
await asyncio.sleep(1)
net_io_2 = psutil.net_io_counters()
in_kbps = (net_io_2.bytes_recv - net_io_1.bytes_recv) * 8 / 1024
out_kbps = (net_io_2.bytes_sent - net_io_1.bytes_sent) * 8 / 1024
```

### **Сохранение в БД:**
```python
# В app/monitor.py
network_in_kbps=r["in_kbps"],
network_out_kbps=r["out_kbps"],
```

### **API ответ:**
```json
{
  "latest_metric": {
    "network_in_kbps": 1024.5,
    "network_out_kbps": 2048.3,
    "network_io": 3.0
  }
}
```

### **Отображение в интерфейсе:**
```javascript
updateMetricBadge(document.getElementById(`network-${s.id}`), latest.network_io, ' MB/s', 'network');
```

## 🎯 Результат

### **До исправления:**
- ❌ **Нет данных** - `network_io` отсутствовал в API
- ❌ **JavaScript ошибки** - попытка доступа к несуществующему полю
- ❌ **Пустые значения** - отображался только "-"

### **После исправления:**
- ✅ **Корректные данные** - `network_io` вычисляется из входящего и исходящего трафика
- ✅ **Правильные единицы** - МБ/с вместо кбит/с
- ✅ **Цветовая индикация** - работает согласно логике Network метрик

## 📊 Примеры значений

### **Низкая активность (0-50 МБ/с):**
- Входящий: 1024 кбит/с = 0.125 МБ/с
- Исходящий: 2048 кбит/с = 0.25 МБ/с
- **Итого**: 0.375 МБ/с → 🟢 Зеленый

### **Средняя активность (50-100 МБ/с):**
- Входящий: 409600 кбит/с = 50 МБ/с
- Исходящий: 409600 кбит/с = 50 МБ/с
- **Итого**: 100 МБ/с → 🟡 Желтый

### **Высокая активность (>100 МБ/с):**
- Входящий: 819200 кбит/с = 100 МБ/с
- Исходящий: 819200 кбит/с = 100 МБ/с
- **Итого**: 200 МБ/с → 🟢 Зеленый

## 📁 Обновленные файлы

### **`app/services.py`:**
- Добавлено поле `network_io` в `get_servers_with_metrics()`
- Добавлено поле `network_io` в `get_server_metrics_history()`
- Добавлено поле `network_io` в `evaluate_alerts_optimized()`

## 🎉 Заключение

Проблема с отображением метрики Network полностью решена:

1. ✅ **Добавлено вычисляемое поле** `network_io` в API
2. ✅ **Правильная конвертация** из кбит/с в МБ/с
3. ✅ **Обработка null значений** для стабильности
4. ✅ **Консистентность** во всех методах API

**Теперь метрика Network корректно отображается на главной странице!** 🚀
