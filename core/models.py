"""Модели данных SecCheck: статусы, уровни обнаружения и результаты проверок и команд."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Status(Enum):
    """Итоговый статус одной проверки."""

    OK = "OK"                      # проверка пройдена
    WARNING = "WARNING"            # работает частично / есть замечания
    FAIL = "FAIL"                  # средство защиты не сработало / отсутствует
    INCONCLUSIVE = "INCONCLUSIVE"  # вывод сделать нельзя (нет сети, недоступна цель)
    NOT_RUN = "NOT_RUN"            # проверку не запускали
    ERROR = "ERROR"                # сбой программы или нехватка прав


class Level(Enum):
    """Уровень обнаружения продукта защиты (модуль M2)."""

    NOT_FOUND = 0
    INSTALLED = 1                  # есть пакет или файлы
    RUNNING = 2                    # служба активна или процесс запущен
    ACTIVE = 3                     # подтверждено, что защита включена


# Типы полей-коллекций записаны как list / dict, а не list[str]: dataclass в Python 3.7
# читает аннотации, и такая запись безопасна. Тип элементов указан в комментарии.

@dataclass
class CheckResult:
    """Результат одной проверки (M1–M4), который модуль возвращает контроллеру."""

    check_id: str                  # "M1".."M4"
    title: str                     # название проверки
    status: Status
    summary: str                   # одна строка для меню
    details: list = field(default_factory=list)   # list[str], строки для отчёта
    data: dict = field(default_factory=dict)      # машинно-читаемые данные для JSON и M3
    started_at: datetime = None    # время запуска, заполняет контроллер
    duration_ms: int = 0           # длительность, заполняет контроллер


@dataclass
class DetectedProduct:
    """Продукт защиты, найденный модулем M2 по профилю из products.json."""

    product_id: str
    name: str
    kinds: list                    # list[str]: ["antivirus"], ["firewall"] или оба
    level: Level
    evidence: list                 # list[str]: ["пакет clamav-daemon установлен", ...]
    verified_profile: bool         # значение поля verified профиля


@dataclass
class CommandResult:
    """Результат запуска внешней команды через адаптер.

    Коды возврата меньше нуля означают, что команда не выполнилась:
    -1 — команда не найдена, -2 — превышен таймаут, -3 — нет права на запуск.
    """

    returncode: int
    stdout: str
    stderr: str
    not_found: bool = False
    timed_out: bool = False
