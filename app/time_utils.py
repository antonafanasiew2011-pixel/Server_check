"""
Утилиты для работы с временем в московском часовом поясе
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

# Московский часовой пояс (UTC+3)
MOSCOW_TZ = timezone(timedelta(hours=3))

def to_moscow_time(utc_time: Optional[datetime]) -> Optional[datetime]:
    """
    Конвертирует UTC время в московское время
    """
    if not utc_time:
        return None
    
    # Если время уже имеет timezone info, конвертируем
    if utc_time.tzinfo is not None:
        return utc_time.astimezone(MOSCOW_TZ)
    
    # Если время naive (без timezone), считаем его UTC
    return utc_time.replace(tzinfo=timezone.utc).astimezone(MOSCOW_TZ)

def format_moscow_time(utc_time: Optional[datetime], format_str: str = '%d.%m.%Y %H:%M:%S') -> str:
    """
    Форматирует время в московском часовом поясе
    """
    if not utc_time:
        return '—'
    
    moscow_time = to_moscow_time(utc_time)
    return moscow_time.strftime(format_str)

def format_moscow_time_short(utc_time: Optional[datetime]) -> str:
    """
    Форматирует время в коротком формате для московского часового пояса
    """
    return format_moscow_time(utc_time, '%H:%M:%S')

def format_moscow_date(utc_time: Optional[datetime]) -> str:
    """
    Форматирует дату в московском часовом поясе
    """
    return format_moscow_time(utc_time, '%d.%m.%Y')
