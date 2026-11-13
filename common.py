"""Общие константы и функции SecCheck: статусы проверок, запуск команд, сведения о системе,
загрузка и проверка файла настроек."""

import json
import os
import re
import subprocess
from typing import List, Optional, Tuple

APP_NAME = "SecCheck"
APP_VERSION = "0.1"

# Статусы проверок. Каждая проверка возвращает один из них.
OK = "OK"                      # проверка пройдена
WARNING = "WARNING"            # работает частично / есть замечания
FAIL = "FAIL"                  # средство защиты не сработало / отсутствует
INCONCLUSIVE = "INCONCLUSIVE"  # вывод сделать нельзя (нет сети, недоступна цель)
NOT_RUN = "NOT_RUN"            # проверку не запускали
ERROR = "ERROR"                # сбой программы или нехватка прав

# Строки подробностей, начинающиеся с этого префикса, печатаются и в кратком выводе
# (без флага -v). Остальные подробности видны только с -v.
BRIEF_PREFIX = "• "

# Особые коды возврата run_cmd(), когда команда вообще не выполнилась.
CMD_NOT_FOUND = -1             # программы нет в системе
CMD_TIMEOUT = -2               # команда не завершилась за отведённое время

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

# Команды, выводящие правила netfilter (используются в M2 и M3), и шаблоны запрещающих
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

# Файл настроек, если не указан флаг --config.
DEFAULT_CONFIG_PATH = "/etc/seccheck/config.json"

# Ожидаемая структура config.json: секция -> {ключ: вид значения}.
# Все секции и ключи обязательны. Виды значений проверяет функция check_value().
CONFIG_SCHEMA = {
    "network": {
        "ru_hosts": "host_list",
        "foreign_hosts": "host_list",
        "tcp_port": "port",
        "tcp_timeout_s": "timeout",
        "ping_timeout_s": "int_timeout",
    },
    "presence": {
        "cmd_timeout_s": "timeout",
    },
    "firewall_test": {
        "host": "host",
        "control_port": "port",
        "test_port": "port",
        "timeout_s": "timeout",
    },
    "antivirus_test": {
        "eicar_dir": "dir_or_null",
        "eicar_timeout_s": "timeout",
        "poll_interval_s": "timeout",
    },
}

# Наибольшее допустимое значение таймаутов и интервалов, с.
MAX_TIMEOUT_S = 300

# Допустимое имя узла. Первый символ — буква или цифра, поэтому имя не может начинаться
# с «-» и не будет принято ping за ключ командной строки (например, «-c100»).
# Используется re.fullmatch: «$» в re.match пропустил бы перевод строки в конце имени.
HOST_NAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9.-]*"
MAX_HOST_NAME_LENGTH = 253


def run_cmd(cmd: List[str], timeout: float) -> Tuple[int, str, str]:
    """Запустить внешнюю команду и вернуть (код возврата, stdout, stderr).

    Команда запускается без оболочки (shell=True не используется), с таймаутом
    и с LC_ALL=C: вывод утилит локализован, а разбираем мы только английский.
    Если программы нет, код равен CMD_NOT_FOUND, если вышло время — CMD_TIMEOUT.

    Вывод читается как байты и декодируется явно, как UTF-8 с заменой ошибочных байтов.
    Текстовый режим (universal_newlines=True) декодировал бы по кодировке локали, а при
    LANG=C в Python 3.5 это ASCII: любой не-ASCII байт в выводе уронил бы программу.
    """
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError:
        return CMD_NOT_FOUND, "", "команда не найдена: " + cmd[0]
    except subprocess.TimeoutExpired:
        # subprocess.run сам завершает процесс, у которого вышло время.
        return CMD_TIMEOUT, "", "команда не завершилась за {} с".format(timeout)
    stdout = completed.stdout.decode("utf-8", "replace")
    stderr = completed.stderr.decode("utf-8", "replace")
    return completed.returncode, stdout, stderr


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
    """Проверить, есть ли запрещающие правила netfilter (шаг 1 в M2 и в M3).

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


def is_root() -> bool:
    """Запущена ли программа с правами root (эффективный UID равен 0)."""
    return os.geteuid() == 0


def os_info() -> str:
    """Название ОС из поля PRETTY_NAME файла /etc/os-release (для заголовка отчёта).

    Если файла нет или поле не найдено, возвращается «Linux».
    """
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as release:
            for line in release:
                if line.startswith("PRETTY_NAME="):
                    value = line.split("=", 1)[1].strip()
                    # Значение обычно в кавычках: PRETTY_NAME="Debian GNU/Linux 12"
                    return value.strip("\"'") or "Linux"
    except OSError:
        pass
    return "Linux"


def is_number(value: object) -> bool:
    """Является ли значение числом (int или float), но не true/false.

    В Python bool — подкласс int, поэтому без явной проверки true из JSON прошло бы
    как число 1.
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_host_name(value: object) -> bool:
    """Является ли значение допустимым именем узла (или IPv4-адресом)."""
    return (isinstance(value, str) and len(value) <= MAX_HOST_NAME_LENGTH
            and re.fullmatch(HOST_NAME_PATTERN, value) is not None)


def check_value(value: object, kind: str) -> Optional[str]:
    """Проверить значение по виду из CONFIG_SCHEMA.

    Вернуть None, если значение подходит, иначе описание того, что ожидалось.
    """
    host_rule = ("латинские буквы, цифры, точка и дефис, первый символ — буква или цифра, "
                 "не длиннее {} символов".format(MAX_HOST_NAME_LENGTH))
    if kind == "port":
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            return "ожидается целое число от 1 до 65535"
    elif kind == "timeout":
        if not is_number(value) or not 0 < value <= MAX_TIMEOUT_S:
            return "ожидается число больше 0 и не больше {}".format(MAX_TIMEOUT_S)
    elif kind == "int_timeout":
        # Значение передаётся в `ping -W`, а старые версии ping принимают только целое.
        if isinstance(value, bool) or not isinstance(value, int) \
                or not 0 < value <= MAX_TIMEOUT_S:
            return "ожидается целое число больше 0 и не больше {}".format(MAX_TIMEOUT_S)
    elif kind == "host":
        if not is_host_name(value):
            return "недопустимое имя узла ({})".format(host_rule)
    elif kind == "host_list":
        if not isinstance(value, list) or len(value) == 0:
            return "ожидается непустой список имён узлов"
        for item in value:
            if not is_host_name(item):
                return "недопустимое имя узла {} ({})".format(
                    json.dumps(item, ensure_ascii=False), host_rule)
    elif kind == "dir_or_null":
        if value is None:
            return None
        if not isinstance(value, str) or not value.startswith("/"):
            return "ожидается null или абсолютный путь к каталогу (начинается с «/»)"
        if not os.path.isdir(value):
            return "каталог не существует"
    else:
        # Сюда попадаем только при опечатке в CONFIG_SCHEMA, то есть при ошибке в коде.
        raise ValueError("неизвестный вид значения в CONFIG_SCHEMA: " + kind)
    return None


def load_config(path: str) -> dict:
    """Прочитать и проверить файл настроек. Вернуть словарь {секция: {ключ: значение}}.

    Любая ошибка (нет файла, неверный JSON, лишний или отсутствующий ключ, неверное
    значение) превращается в ValueError с текстом, где указаны файл, секция и ключ.
    """
    if not os.path.exists(path):
        raise ValueError("Файл настроек не найден: {}. Установите программу "
                         "(sudo ./install.sh) или укажите файл: --config ./config.json"
                         .format(path))
    try:
        with open(path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except json.JSONDecodeError as exc:
        raise ValueError("{}: ошибка JSON в строке {}, столбце {}: {}".format(
            path, exc.lineno, exc.colno, exc.msg))
    except UnicodeDecodeError:
        raise ValueError("{}: файл не в кодировке UTF-8".format(path))
    except OSError as exc:
        raise ValueError("{}: не удалось прочитать файл: {}".format(path, exc.strerror))

    if not isinstance(config, dict):
        raise ValueError("{}: ожидается объект JSON {{...}} с секциями настроек".format(path))

    # Неизвестные секции и ключи — ошибка: так ловятся опечатки.
    for section in config:
        if section not in CONFIG_SCHEMA:
            raise ValueError("{}: неизвестная секция {}".format(
                path, json.dumps(section, ensure_ascii=False)))

    for section, keys in CONFIG_SCHEMA.items():
        if section not in config:
            raise ValueError('{}: нет секции "{}"'.format(path, section))
        if not isinstance(config[section], dict):
            raise ValueError('{}: секция "{}" должна быть объектом {{...}}'.format(
                path, section))
        for key in config[section]:
            if key not in keys:
                raise ValueError('{}: секция "{}": неизвестный ключ {}'.format(
                    path, section, json.dumps(key, ensure_ascii=False)))
        for key, kind in keys.items():
            if key not in config[section]:
                raise ValueError('{}: секция "{}": нет ключа "{}"'.format(path, section, key))
            value = config[section][key]
            problem = check_value(value, kind)
            if problem is not None:
                raise ValueError('{}: секция "{}", ключ "{}": {}, получено {}'.format(
                    path, section, key, problem, json.dumps(value, ensure_ascii=False)))

    firewall = config["firewall_test"]
    if firewall["control_port"] == firewall["test_port"]:
        raise ValueError('{}: секция "firewall_test": ключи "control_port" и "test_port" '
                         'должны различаться (контрольный порт разрешён, тестовый запрещён '
                         'правилом МЭ)'.format(path))
    return config
