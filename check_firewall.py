"""M3. Проверка работоспособности межсетевого экрана (МЭ).

Отвечает на вопрос: блокирует ли МЭ соединение, запрещённое тестовым правилом.

Проверяющий заранее создаёт правило, запрещающее исходящие соединения на тестовый порт
(команды в README.md). Программа подключается к одному и тому же IP-адресу на два порта:
контрольный (разрешён) и тестовый (запрещён). Имя разрешается один раз, поэтому
провайдерская блокировка по IP исключена: если контрольный порт доступен, а тестовый нет,
соединение запретил локальный МЭ.

Перед подключениями проверяется, есть ли в netfilter запрещающие правила. Если их нет
совсем, МЭ пропускает весь трафик и проверять нечего.
"""

import re
import socket
import time
from typing import List, Optional, Tuple

from common import CMD_NOT_FOUND, FAIL, INCONCLUSIVE, OK, run_cmd

# Настройки берутся из секции "firewall_test" файла настроек (см. README.md, «Настройки»):
#   host         — узел для обоих подключений;
#   control_port — разрешённый порт;
#   test_port    — порт, запрещённый тестовым правилом;
#   timeout_s    — таймаут одного подключения и одной команды nft/iptables, с.

# Запрещающие правила в выводе `iptables -S` (и `iptables-legacy -S`): политика цепочки
# DROP или правило с действием DROP/REJECT. Вывод iptables всегда в верхнем регистре.
# Ищутся именно действия: имена цепочек вроде «ufw-reject-output» есть и при выключенном
# ufw, поэтому простой поиск слов drop/reject в тексте давал ложное срабатывание.
IPTABLES_DENY_PATTERNS = [
    r"^-P\s+(INPUT|OUTPUT|FORWARD)\s+DROP\b",  # -P OUTPUT DROP
    r"\s-j\s+(DROP|REJECT)\b",                  # -A ... -j DROP
]

# Запрещающие правила в выводе `nft list ruleset` (без учёта регистра): политика цепочки
# drop или действие drop/reject отдельным словом. Слово должно быть отделено пробелами
# (или стоять перед «;»/концом строки), поэтому «jump ufw-reject-output» не подходит.
NFT_DENY_PATTERNS = [
    r"\bpolicy\s+drop\b",                       # policy drop;
    r"(^|\s)(drop|reject)(\s|;|$)",              # tcp dport 80 counter drop
]

# Команды, выводящие правила netfilter, и шаблоны запрещающих
# строк для каждой: (команда, шаблоны, искать без учёта регистра). Правила iptables-legacy
# не видны через nft, поэтому смотрим все источники.
NETFILTER_COMMANDS = [
    (["nft", "list", "ruleset"], NFT_DENY_PATTERNS, True),
    (["iptables", "-S"], IPTABLES_DENY_PATTERNS, False),
    (["iptables-legacy", "-S"], IPTABLES_DENY_PATTERNS, False),
]

# Сколько найденных запрещающих строк показывать в подробностях.
MAX_SHOWN_DENY_LINES = 5

# Ширина строки подробностей: вывод до 100 символов, из них 9 занимает отступ.
DETAIL_WIDTH = 91


def is_deny_line(line: str, patterns: List[str], ignore_case: bool) -> bool:
    """Подходит ли строка вывода правил хотя бы под один шаблон запрещающего правила."""
    flags = re.IGNORECASE if ignore_case else 0
    for pattern in patterns:
        if re.search(pattern, line, flags) is not None:
            return True
    return False


def legacy_tables_in_use(timeout_s: float) -> bool:
    """Используются ли legacy-таблицы iptables.

    Да, если `iptables -V` сообщает «(legacy)» или модуль ядра ip_tables уже загружен
    (строка ip_tables в /proc/modules). Иначе `iptables-legacy -S` запускать нельзя:
    сам вызов загрузил бы модуль и создал таблицы в ядре, а программа ничего не меняет
    в системе.
    """
    code, stdout, _stderr = run_cmd(["iptables", "-V"], timeout=timeout_s)
    if code == 0 and "(legacy)" in stdout:
        return True
    try:
        with open("/proc/modules", "r", encoding="utf-8", errors="replace") as modules:
            for line in modules:
                # Строка файла: «ip_tables 32768 0 - Live 0x...», первое слово — имя модуля.
                if line.split(" ", 1)[0] == "ip_tables":
                    return True
    except OSError:
        pass
    return False


def check_netfilter(timeout_s: float) -> Tuple[bool, List[str], bool]:
    """Шаг 1. Проверить, есть ли запрещающие правила netfilter.

    Вернуть (фильтрация включена, подробности, удалось ли прочитать хоть один источник).
    Фильтрация считается включённой, если хотя бы одна строка вывода правил подходит под
    шаблоны IPTABLES_DENY_PATTERNS или NFT_DENY_PATTERNS. Первые MAX_SHOWN_DENY_LINES
    найденных строк попадают в подробности, чтобы было видно, на что сработала проверка.
    """
    any_read = False
    details = []
    deny_lines = []  # найденные запрещающие строки: «команда: строка»
    for cmd, patterns, ignore_case in NETFILTER_COMMANDS:
        command_text = " ".join(cmd)
        if cmd[0] == "iptables-legacy" and not legacy_tables_in_use(timeout_s):
            details.append("{}: не выполнялась (legacy-таблицы не используются)".format(
                command_text))
            continue
        code, stdout, stderr = run_cmd(cmd, timeout=timeout_s)
        if code == CMD_NOT_FOUND:
            details.append("{}: утилита не установлена".format(command_text))
            continue
        if code != 0:
            # Для подробностей берём первую строку сообщения об ошибке, а если её нет —
            # код возврата. Длинное сообщение обрезаем: ширина отчёта до 100 символов.
            lines = stderr.strip().splitlines()
            if lines:
                reason = lines[0]
            else:
                reason = "код " + str(code)
            if len(reason) > 50:
                reason = reason[:47] + "..."
            details.append("{}: не выполнена ({})".format(command_text, reason))
            continue
        any_read = True
        found = 0
        for line in stdout.splitlines():
            if is_deny_line(line, patterns, ignore_case):
                found += 1
                deny_lines.append("{}: {}".format(command_text, line.strip()))
        if found > 0:
            details.append("{}: запрещающих правил: {}".format(command_text, found))
        else:
            details.append("{}: запрещающих правил нет".format(command_text))

    if len(deny_lines) > MAX_SHOWN_DENY_LINES:
        details.append("Запрещающие правила (первые {} из {}):".format(
            MAX_SHOWN_DENY_LINES, len(deny_lines)))
    elif deny_lines:
        details.append("Запрещающие правила:")
    if deny_lines:
        for line in deny_lines[:MAX_SHOWN_DENY_LINES]:
            line = "  " + line
            if len(line) > DETAIL_WIDTH:
                line = line[:DETAIL_WIDTH - 3] + "..."
            details.append(line)
    return len(deny_lines) > 0, details, any_read


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
    """Шаг 7. Описать тип отказа в подключении к тестовому порту (для подробностей)."""
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


def run(cfg: dict) -> Tuple[str, List[str], List[str]]:
    """Выполнить проверку M3. Вернуть (статус, краткие строки, подробности).

    cfg — секция "firewall_test" файла настроек.
    """
    host = cfg["host"]
    control_port = cfg["control_port"]
    test_port = cfg["test_port"]
    timeout_s = cfg["timeout_s"]

    # Шаг 1. Есть ли в netfilter запрещающие правила.
    filtering, netfilter_details, netfilter_read = check_netfilter(timeout_s)
    details = []
    if not netfilter_read:
        # Например, нет прав root: проверка идёт дальше, но без этого вывода.
        details.append("Наличие запрещающих правил не проверено: правила netfilter не прочитаны")
    # Причины, по которым источники не прочитаны, или найденные запрещающие строки.
    details.extend(netfilter_details)
    if netfilter_read and not filtering:
        return INCONCLUSIVE, ["не определена — запрещающих правил нет",
                              "Создайте запрещающее правило для тестового порта",
                              "(firewall_test.test_port в файле настроек) и включите МЭ"
                              ], details

    # Шаг 2. Разрешить имя в IPv4 один раз.
    try:
        addresses = socket.getaddrinfo(host, control_port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        details.append("Ошибка разрешения имени: {}".format(exc))
        return INCONCLUSIVE, ["не определена — имя узла {} не разрешается (DNS)".format(host)
                              ], details
    ip = addresses[0][4][0]
    details.append("Узел: {} ({})".format(host, ip))

    # Шаг 3. Контрольное подключение.
    error, ms = connect(ip, control_port, timeout_s)
    if error is not None:
        details.append("Контрольный порт {}: недоступен ({})".format(control_port, error))
        return INCONCLUSIVE, ["не определена — контрольный узел недоступен"], details
    details.append("Контрольный порт {}: доступен ({} мс)".format(control_port, ms))

    # Шаг 4. Тестовое подключение на тот же IP.
    error, ms = connect(ip, test_port, timeout_s)
    if error is None:
        # Шаг 5.
        details.append("Тестовый порт {}: соединение установлено ({} мс)".format(test_port, ms))
        return FAIL, ["запрещённое соединение не заблокировано",
                      "Проверьте, что запрещающее правило создано и МЭ включён"], details

    # Шаги 6–7.
    details.append("Тестовый порт {}: соединение не установлено ({} мс)".format(test_port, ms))
    details.extend(describe_refusal(error, timeout_s))
    return OK, ["запрещённое соединение заблокировано"], details
