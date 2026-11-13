"""M3. Проверка работоспособности межсетевого экрана (МЭ).

Проверяющий заранее создаёт правило, запрещающее исходящие соединения на TEST_PORT
(команды в README.md). Программа подключается к одному и тому же IP-адресу на два порта:
контрольный (разрешён) и тестовый (запрещён). Имя разрешается один раз, поэтому
провайдерская блокировка по IP исключена: если контрольный порт доступен, а тестовый нет,
соединение запретил локальный МЭ.
"""

from __future__ import annotations

import socket
import time
from typing import List, Optional, Tuple

from common import FAIL, INCONCLUSIVE, OK

# Настройки проверки.
FW_HOST = "ya.ru"     # узел для обоих подключений
CONTROL_PORT = 443    # разрешённый порт
TEST_PORT = 80        # порт, запрещённый тестовым правилом
TIMEOUT = 3           # таймаут одного подключения, с


def connect(ip: str, port: int) -> Tuple[Optional[OSError], int]:
    """Подключиться к ip:port. Вернуть (None или ошибка подключения, время в мс)."""
    start = time.monotonic()
    try:
        connection = socket.create_connection((ip, port), timeout=TIMEOUT)
    except OSError as exc:
        return exc, int((time.monotonic() - start) * 1000)
    connection.close()
    return None, int((time.monotonic() - start) * 1000)


def describe_refusal(error: OSError) -> List[str]:
    """Шаг 6. Описать тип отказа в подключении к тестовому порту."""
    if isinstance(error, PermissionError):
        # Ядро сразу возвращает EPERM, если исходящий пакет отброшен netfilter.
        # TODO(стенд): подтвердить на стенде с `ufw deny out`.
        return ["Тип отказа: соединение запрещено локальным МЭ (EPERM)"]
    if isinstance(error, ConnectionRefusedError):
        return ["Тип отказа: соединение отклонено (правило REJECT)"]
    if isinstance(error, socket.timeout):
        return ["Тип отказа: соединение не установлено за {} с (вероятно, правило DROP)"
                .format(TIMEOUT),
                "Таймаут косвенно указывает на МЭ: контрольный порт на том же адресе доступен"]
    return ["Тип отказа: другая ошибка ({})".format(error)]


def run() -> Tuple[str, List[str]]:
    """Выполнить проверку M3. Вернуть (статус, [итог, подробности...])."""
    # Шаг 1. Разрешить имя в IPv4 один раз.
    try:
        addresses = socket.getaddrinfo(FW_HOST, CONTROL_PORT, socket.AF_INET,
                                       socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return INCONCLUSIVE, ["Не удалось разрешить имя " + FW_HOST,
                              "Ошибка: {}".format(exc)]
    ip = addresses[0][4][0]
    details = ["Узел: {} ({})".format(FW_HOST, ip)]

    # Шаг 2. Контрольное подключение.
    error, ms = connect(ip, CONTROL_PORT)
    if error is not None:
        details.append("Контрольный порт {}: недоступен ({})".format(CONTROL_PORT, error))
        return INCONCLUSIVE, ["Контрольная цель недоступна, вывод о работе МЭ сделать нельзя"
                              ] + details
    details.append("Контрольный порт {}: доступен ({} мс)".format(CONTROL_PORT, ms))

    # Шаг 3. Тестовое подключение на тот же IP.
    error, ms = connect(ip, TEST_PORT)
    if error is None:
        # Шаг 4.
        details.append("Тестовый порт {}: соединение установлено ({} мс)".format(TEST_PORT, ms))
        details.append("Создайте тестовое правило по README.md и повторите проверку")
        return FAIL, ["МЭ пропустил соединение, которое должен был запретить. "
                      "Правило не создано или МЭ не работает"] + details

    # Шаги 5–6.
    details.append("Тестовый порт {}: соединение не установлено ({} мс)".format(TEST_PORT, ms))
    details.extend(describe_refusal(error))
    return OK, ["МЭ работает: соединение {}:{} запрещено".format(ip, TEST_PORT)] + details
