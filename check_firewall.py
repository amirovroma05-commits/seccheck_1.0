"""M3. Проверка работоспособности межсетевого экрана (МЭ).

Проверяющий заранее создаёт правило, запрещающее исходящие соединения на тестовый порт
(команды в README.md). Программа подключается к одному и тому же IP-адресу на два порта:
контрольный (разрешён) и тестовый (запрещён). Имя разрешается один раз, поэтому
провайдерская блокировка по IP исключена: если контрольный порт доступен, а тестовый нет,
соединение запретил локальный МЭ.

Перед подключениями проверяется, есть ли в netfilter запрещающие правила (та же функция
common.check_netfilter, что и в M2; от запуска M2 проверка не зависит). Если правил нет
совсем, МЭ пропускает весь трафик и проверять нечего.
"""

import socket
import time
from typing import List, Optional, Tuple

from common import FAIL, INCONCLUSIVE, OK, check_netfilter

# Настройки берутся из секции "firewall_test" файла настроек (см. README.md, «Настройки»):
#   host         — узел для обоих подключений;
#   control_port — разрешённый порт;
#   test_port    — порт, запрещённый тестовым правилом;
#   timeout_s    — таймаут одного подключения и одной команды nft/iptables, с.


def connect(ip: str, port: int, timeout_s: float) -> Tuple[Optional[OSError], int]:
    """Подключиться к ip:port. Вернуть (None или ошибка подключения, время в мс)."""
    start = time.monotonic()
    try:
        connection = socket.create_connection((ip, port), timeout=timeout_s)
    except OSError as exc:
        return exc, int((time.monotonic() - start) * 1000)
    connection.close()
    return None, int((time.monotonic() - start) * 1000)


def describe_refusal(error: OSError, timeout_s: float) -> List[str]:
    """Шаг 7. Описать тип отказа в подключении к тестовому порту."""
    if isinstance(error, PermissionError):
        # Ядро сразу возвращает EPERM, если исходящий пакет отброшен netfilter.
        # TODO(стенд): подтвердить на стенде с `ufw deny out`.
        return ["Тип отказа: соединение запрещено локальным МЭ (EPERM)"]
    if isinstance(error, ConnectionRefusedError):
        return ["Тип отказа: соединение отклонено (правило REJECT)"]
    if isinstance(error, socket.timeout):
        return ["Тип отказа: соединение не установлено за {} с (вероятно, правило DROP)"
                .format(timeout_s),
                "Таймаут косвенно указывает на МЭ: контрольный порт на том же адресе доступен"]
    return ["Тип отказа: другая ошибка ({})".format(error)]


def run(cfg: dict) -> Tuple[str, List[str]]:
    """Выполнить проверку M3. Вернуть (статус, [итог, подробности...]).

    cfg — секция "firewall_test" файла настроек.
    """
    host = cfg["host"]
    control_port = cfg["control_port"]
    test_port = cfg["test_port"]
    timeout_s = cfg["timeout_s"]

    # Шаг 1. Есть ли в netfilter запрещающие правила.
    filtering, netfilter_details, netfilter_read = check_netfilter(timeout_s)
    if netfilter_read and not filtering:
        return INCONCLUSIVE, ["Запрещающих правил нет — МЭ пропускает весь трафик, "
                              "проверять нечего",
                              "Создайте тестовое правило (README)",
                              "Если используете ufw — убедитесь, что он включён: "
                              "sudo ufw status"] + netfilter_details
    details = []
    if not netfilter_read:
        # Например, нет прав root: проверка идёт дальше, но без этого вывода.
        details.append("Наличие запрещающих правил не проверено: правила netfilter не прочитаны")
    # Причины, по которым источники не прочитаны, или найденные запрещающие строки.
    details.extend(netfilter_details)

    # Шаг 2. Разрешить имя в IPv4 один раз.
    try:
        addresses = socket.getaddrinfo(host, control_port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return INCONCLUSIVE, ["Не удалось разрешить имя " + host,
                              "Ошибка: {}".format(exc)] + details
    ip = addresses[0][4][0]
    details.append("Узел: {} ({})".format(host, ip))

    # Шаг 3. Контрольное подключение.
    error, ms = connect(ip, control_port, timeout_s)
    if error is not None:
        details.append("Контрольный порт {}: недоступен ({})".format(control_port, error))
        return INCONCLUSIVE, ["Контрольная цель недоступна, вывод о работе МЭ сделать нельзя"
                              ] + details
    details.append("Контрольный порт {}: доступен ({} мс)".format(control_port, ms))

    # Шаг 4. Тестовое подключение на тот же IP.
    error, ms = connect(ip, test_port, timeout_s)
    if error is None:
        # Шаг 5.
        details.append("Тестовый порт {}: соединение установлено ({} мс)".format(test_port, ms))
        details.append("Создайте тестовое правило по README.md и повторите проверку")
        return FAIL, ["Тестовый порт не заблокирован: правила для него нет "
                      "или МЭ его не применяет"] + details

    # Шаги 6–7.
    details.append("Тестовый порт {}: соединение не установлено ({} мс)".format(test_port, ms))
    details.extend(describe_refusal(error, timeout_s))
    return OK, ["МЭ работает: соединение {}:{} запрещено".format(ip, test_port)] + details
