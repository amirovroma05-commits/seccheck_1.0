"""M1. Проверка подключения к интернету.

Узлы делятся на две группы, российские и зарубежные, чтобы отличить полный доступ
от ограниченного (белые списки мобильных операторов, блокировки). ICMP часто режется,
поэтому решение принимается по TCP-подключению, а ping выводится только для сведения.
"""

from __future__ import annotations

import socket
import time
from typing import List, Tuple

from common import FAIL, OK, WARNING, run_cmd

# Настройки проверки.
RU_HOSTS = ["ya.ru", "vk.com"]
FOREIGN_HOSTS = ["example.com", "github.com"]
TCP_PORT = 443        # порт для TCP-подключения
TCP_TIMEOUT = 3       # таймаут одного TCP-подключения, с
PING_TIMEOUT = 2      # время ожидания ответа на ping, с (целое число)


def ping(host: str) -> bool:
    """Отправить узлу один ICMP-запрос; True, если пришёл ответ."""
    code, _stdout, _stderr = run_cmd(["ping", "-c", "1", "-W", str(PING_TIMEOUT), host],
                                     timeout=PING_TIMEOUT + 3)
    return code == 0


def tcp_connect(host: str) -> Tuple[bool, int, bool]:
    """Подключиться к host:TCP_PORT. Вернуть (успех, время в мс, ошибка DNS).

    socket.gaierror — имя не разрешилось (ошибка DNS); его проверяем раньше OSError,
    потому что gaierror является подклассом OSError.
    """
    start = time.monotonic()
    try:
        connection = socket.create_connection((host, TCP_PORT), timeout=TCP_TIMEOUT)
    except socket.gaierror:
        return False, 0, True
    except OSError:
        return False, int((time.monotonic() - start) * 1000), False
    connection.close()
    return True, int((time.monotonic() - start) * 1000), False


def run() -> Tuple[str, List[str]]:
    """Выполнить проверку M1. Вернуть (статус, [итог, подробности...])."""
    # Шаг 1. Все узлы с пометкой группы.
    hosts = []
    for host in RU_HOSTS:
        hosts.append(("ru", host))
    for host in FOREIGN_HOSTS:
        hosts.append(("foreign", host))

    # Шаги 2–3. Для каждого узла: ping (для сведения) и TCP-подключение.
    checked = []  # список словарей с результатами по узлам
    for group, host in hosts:
        icmp = ping(host)
        tcp, ms, dns_error = tcp_connect(host)
        checked.append({"group": group, "host": host, "icmp": icmp, "tcp": tcp,
                        "ms": ms, "dns_error": dns_error})

    # Шаг 4. Группа доступна, если хотя бы один её узел ответил по TCP.
    ru_ok = False
    foreign_ok = False
    for item in checked:
        if item["tcp"] and item["group"] == "ru":
            ru_ok = True
        if item["tcp"] and item["group"] == "foreign":
            foreign_ok = True

    # Шаг 8. Подробности по каждому узлу.
    details = []
    for item in checked:
        if item["dns_error"]:
            tcp_text = "нет (ошибка DNS)"
        elif item["tcp"]:
            tcp_text = "да  ({} мс)".format(item["ms"])
        else:
            tcp_text = "нет"
        details.append("{:<14} ICMP: {:<4} TCP {}: {}".format(
            item["host"], "да" if item["icmp"] else "нет", TCP_PORT, tcp_text))

    any_icmp = any(item["icmp"] for item in checked)
    any_tcp = any(item["tcp"] for item in checked)
    if any_tcp and not any_icmp:
        details.append("ICMP блокируется: ни один узел не ответил на ping")

    # Шаги 5–7. Итоговый статус.
    if not ru_ok and not foreign_ok:
        if all(item["dns_error"] for item in checked):
            details.append("Не работает разрешение имён (DNS)")
        return FAIL, ["Нет подключения к интернету"] + details
    if ru_ok and foreign_ok:
        return OK, ["Подключение к интернету есть"] + details
    if ru_ok:
        summary = "Доступ к интернету ограничен: доступны только российские узлы"
    else:
        summary = "Доступ к интернету ограничен: доступны только зарубежные узлы"
    return WARNING, [summary] + details
