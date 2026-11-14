"""Общие константы и функции SecCheck: статусы проверок, запуск команд, сведения о системе,
чтение JSON-файлов, загрузка и проверка файла настроек."""

import json
import os
import re
import subprocess
from collections import OrderedDict
from typing import List, Tuple

APP_NAME = "SecCheck"
APP_VERSION = "0.1"

# Статусы проверок. Каждая проверка возвращает один из них.
OK = "OK"                      # проверка пройдена
WARNING = "WARNING"            # работает частично / есть замечания
FAIL = "FAIL"                  # средство защиты не сработало / отсутствует
INCONCLUSIVE = "INCONCLUSIVE"  # вывод сделать нельзя (нет сети, недоступна цель)
NOT_RUN = "NOT_RUN"            # проверку не запускали
ERROR = "ERROR"                # сбой программы или нехватка прав

# Особые коды возврата run_cmd(), когда команда вообще не выполнилась.
CMD_NOT_FOUND = -1             # программы нет в системе
CMD_TIMEOUT = -2               # команда не завершилась за отведённое время

# Файл настроек. Его создаёт install.sh при первой установке.
DEFAULT_CONFIG_PATH = "/etc/seccheck/config.json"

# Ожидаемая структура config.json: секция -> {ключ: вид значения}.
# Все перечисленные ключи обязательны, другие секции и ключи игнорируются (например,
# ключи из прежних версий). Виды значений проверяет функция check_value().
CONFIG_SCHEMA = {
    "network": {
        "ru_hosts": "host_list",
        "foreign_hosts": "host_list",
        "tcp_port": "port",
        "tcp_timeout_s": "timeout",
    },
    "presence": {
        "cmd_timeout_s": "timeout",
    },
    "firewall_test": {
        "host": "host",
        "test_port": "port",
        "timeout_s": "timeout",
    },
    "antivirus_test": {
        "eicar_timeout_s": "timeout",
        "poll_interval_s": "timeout",
    },
}

# Наибольшее допустимое значение таймаутов и интервалов, с.
MAX_TIMEOUT_S = 300

# Допустимое имя узла. Программа работает от root, а адрес узла M3 попадает в команду ufw,
# поэтому имя проверяется заранее: только буквы, цифры, точка и дефис, первый символ —
# буква или цифра (имя не может начинаться с «-» и быть принято за ключ команды).
# Используется re.fullmatch: «$» в re.match пропустил бы перевод строки в конце имени.
HOST_NAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9.-]*"
MAX_HOST_NAME_LENGTH = 253


def run_cmd(cmd: List[str], timeout: float) -> Tuple[int, str, str]:
    """Запустить внешнюю команду и вернуть (код возврата, stdout, stderr).

    Команда запускается без оболочки (shell=True не используется), с таймаутом
    и с LC_ALL=C и LANGUAGE=C: вывод утилит локализован, а разбираем мы только английский.
    Если программы нет, код равен CMD_NOT_FOUND, если вышло время — CMD_TIMEOUT.

    Вывод читается как байты и декодируется явно, как UTF-8 с заменой ошибочных байтов.
    Текстовый режим (universal_newlines=True) декодировал бы по кодировке локали, а при
    LANG=C в Python 3.5 это ASCII: любой не-ASCII байт в выводе уронил бы программу.
    """
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    # Программы на Python (например, ufw) переводят сообщения через модуль gettext, а он
    # смотрит переменную LANGUAGE раньше LC_ALL. Поэтому она тоже сбрасывается.
    env["LANGUAGE"] = "C"
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


def check_value(value: object, kind: str) -> bool:
    """Подходит ли значение под вид из CONFIG_SCHEMA."""
    if kind == "port":
        return is_number(value) and isinstance(value, int) and 1 <= value <= 65535
    if kind == "timeout":
        return is_number(value) and 0 < value <= MAX_TIMEOUT_S
    if kind == "host":
        return is_host_name(value)
    if kind == "host_list":
        if not isinstance(value, list) or len(value) == 0:
            return False
        for item in value:
            if not is_host_name(item):
                return False
        return True
    # Неизвестный вид возможен только при опечатке в CONFIG_SCHEMA.
    return False


def load_json(path: str) -> object:
    """Прочитать JSON-файл в кодировке UTF-8 и вернуть его содержимое.

    object_pairs_hook=OrderedDict сохраняет порядок ключей как в файле (в Python 3.5
    обычный словарь его не сохраняет). Любая ошибка чтения или разбора (нет файла, нет
    прав, не UTF-8, ошибка синтаксиса) даёт одно общее сообщение. JSONDecodeError
    и UnicodeDecodeError — подклассы ValueError.
    """
    try:
        with open(path, "r", encoding="utf-8") as json_file:
            return json.load(json_file, object_pairs_hook=OrderedDict)
    except (OSError, ValueError):
        raise ValueError("{}: файл не найден или не является корректным JSON".format(path))


def load_config(path: str) -> dict:
    """Прочитать и проверить файл настроек. Вернуть словарь {секция: {ключ: значение}}.

    Проверяется только, что каждый ключ из CONFIG_SCHEMA есть и его значение подходит
    по виду. Любая ошибка — ValueError с одним сообщением.
    """
    if not os.path.exists(path):
        raise ValueError("Файл настроек не найден: {}. Установите программу: "
                         "sudo ./install.sh".format(path))
    config = load_json(path)
    for section, keys in CONFIG_SCHEMA.items():
        # Нет секции или она не объект — значит, нет и её ключей.
        values = {}
        if isinstance(config, dict) and isinstance(config.get(section), dict):
            values = config[section]
        for key, kind in keys.items():
            if key not in values or not check_value(values[key], kind):
                raise ValueError("{}: некорректное значение {}.{}".format(path, section, key))
    return config
