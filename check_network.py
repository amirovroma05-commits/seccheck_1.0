"""M1. Проверка подключения к интернету.

Отвечает на вопрос: есть ли подключение к интернету (полное или ограниченное).

Узлы делятся на две группы, российские и зарубежные, чтобы отличить полный доступ
от ограниченного (белые списки мобильных операторов, блокировки). Решение принимается
по TCP-подключению; ping не используется, потому что ICMP часто режется.
"""

import socket
import time
from typing import List, Tuple

from common import FAIL, OK, WARNING

# Настройки берутся из секции "network" файла настроек (см. README.md, «Настройки»):
#   ru_hosts, foreign_hosts — группы узлов;
#   tcp_port               — порт для TCP-подключения;
#   tcp_timeout_s          — таймаут одного TCP-подключения, с.


def tcp_connect(host: str, port: int, timeout_s: float) -> Tuple[bool, int, bool]:
    """Подключиться к host:port. Вернуть (успех, время в мс, ошибка DNS).

    socket.gaierror — имя не разрешилось (ошибка DNS); его проверяем раньше OSError,
    потому что gaierror является подклассом OSError.
    """
    start = time.monotonic()
    try:
        connection = socket.create_connection((host, port), timeout=timeout_s)
    except socket.gaierror:
        return False, 0, True
    except OSError:
        return False, int((time.monotonic() - start) * 1000), False
    connection.close()
    return True, int((time.monotonic() - start) * 1000), False


def check_group(hosts: List[str], port: int, timeout_s: float) -> Tuple[bool, bool, List[str]]:
    """Шаги 2–3. Подключиться по TCP к каждому узлу группы по очереди.

    Вернуть (ответил ли хотя бы один узел, у всех ли узлов ошибка DNS, строки подробностей).
    Строка подробностей — имя узла и результат TCP: да с временем, нет или ошибка DNS.
    """
    any_ok = False
    all_dns_errors = True
    lines = []
    for host in hosts:
        ok, ms, dns_error = tcp_connect(host, port, timeout_s)
        if ok:
            any_ok = True
            result = "да  ({} мс)".format(ms)
        elif dns_error:
            result = "нет (ошибка DNS)"
        else:
            result = "нет"
        if not dns_error:
            all_dns_errors = False
        lines.append("{:<14} TCP {}: {}".format(host, port, result))
    return any_ok, all_dns_errors, lines


def run(cfg: dict) -> Tuple[str, List[str], List[str]]:
    """Выполнить проверку M1. Вернуть (статус, краткие строки, подробности).

    cfg — секция "network" файла настроек.
    """
    port = cfg["tcp_port"]
    timeout_s = cfg["tcp_timeout_s"]
    # Шаг 1. Проверить группу ru_hosts, затем foreign_hosts (шаги 2–3 — в check_group).
    ru_ok, ru_dns_errors, ru_lines = check_group(cfg["ru_hosts"], port, timeout_s)
    foreign_ok, foreign_dns_errors, foreign_lines = check_group(cfg["foreign_hosts"], port,
                                                                timeout_s)
    # Подробности (только для -v): строки по узлам обеих групп.
    details = ru_lines + foreign_lines

    # Шаги 4–6. Итоговый статус.
    if not ru_ok and not foreign_ok:
        if ru_dns_errors and foreign_dns_errors:
            details.append("Не работает DNS: ни одно имя узла не разрешилось")
        return FAIL, ["нет"], details
    if ru_ok and foreign_ok:
        return OK, ["есть"], details
    if ru_ok:
        return WARNING, ["ограничено (доступны только российские узлы)"], details
    return WARNING, ["ограничено (доступны только зарубежные узлы)"], details
