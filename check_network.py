"""M1. Проверка подключения к интернету.

Отвечает на вопрос: есть ли подключение к интернету (полное или ограниченное).

Узлы делятся на две группы, российские и зарубежные, чтобы отличить полный доступ
от ограниченного (белые списки мобильных операторов, блокировки). ICMP часто режется,
поэтому решение принимается по TCP-подключению, а ping выводится только для сведения.
"""

import socket
import time
from typing import List, Tuple

from common import FAIL, OK, WARNING, run_cmd

# Настройки берутся из секции "network" файла настроек (см. README.md, «Настройки»):
#   ru_hosts, foreign_hosts — группы узлов;
#   tcp_port               — порт для TCP-подключения;
#   tcp_timeout_s          — таймаут одного TCP-подключения, с;
#   ping_timeout_s         — время ожидания ответа на ping, с (целое число).


def ping(host: str, timeout_s: int) -> bool:
    """Отправить узлу один ICMP-запрос; True, если пришёл ответ.

    Имя узла уже проверено load_config(): оно не начинается с «-», поэтому ping
    не примет его за ключ.
    """
    code, _stdout, _stderr = run_cmd(["ping", "-c", "1", "-W", str(timeout_s), host],
                                     timeout=timeout_s + 3)
    return code == 0


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


def run(cfg: dict) -> Tuple[str, List[str], List[str]]:
    """Выполнить проверку M1. Вернуть (статус, краткие строки, подробности).

    cfg — секция "network" файла настроек.
    """
    port = cfg["tcp_port"]
    # Шаг 1. Все узлы с пометкой группы.
    hosts = []
    for host in cfg["ru_hosts"]:
        hosts.append(("ru", host))
    for host in cfg["foreign_hosts"]:
        hosts.append(("foreign", host))

    # Шаги 2–3. Для каждого узла: ping (для сведения) и TCP-подключение.
    checked = []  # список словарей с результатами по узлам
    for group, host in hosts:
        icmp = ping(host, cfg["ping_timeout_s"])
        tcp, ms, dns_error = tcp_connect(host, port, cfg["tcp_timeout_s"])
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

    # Шаг 8. Подробности по каждому узлу (только для -v).
    details = []
    for item in checked:
        if item["dns_error"]:
            tcp_text = "нет (ошибка DNS)"
        elif item["tcp"]:
            tcp_text = "да  ({} мс)".format(item["ms"])
        else:
            tcp_text = "нет"
        details.append("{:<14} ICMP: {:<4} TCP {}: {}".format(
            item["host"], "да" if item["icmp"] else "нет", port, tcp_text))

    any_icmp = any(item["icmp"] for item in checked)
    any_tcp = any(item["tcp"] for item in checked)
    if any_tcp and not any_icmp:
        details.append("ICMP блокируется: ни один узел не ответил на ping")

    # Шаги 5–7. Итоговый статус.
    if not ru_ok and not foreign_ok:
        if all(item["dns_error"] for item in checked):
            details.append("Не работает DNS: ни одно имя узла не разрешилось")
        return FAIL, ["нет"], details
    if ru_ok and foreign_ok:
        return OK, ["есть"], details
    if ru_ok:
        return WARNING, ["ограничено (доступны только российские узлы)"], details
    return WARNING, ["ограничено (доступны только зарубежные узлы)"], details
