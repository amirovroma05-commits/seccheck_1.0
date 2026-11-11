"""Загрузка и проверка файла настроек data/config.json.

Проверка products.json добавится на этапе 4 вместе с модулем M2.
"""

from __future__ import annotations

import json
import os
from typing import Optional

# Корневой каталог проекта (на уровень выше каталога core/).
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Путь к настройкам по умолчанию. Он считается от каталога проекта, а не от текущего
# каталога, чтобы `sudo python3 /путь/main.py` работал из любого места.
DEFAULT_CONFIG_PATH = os.path.join(PROJECT_DIR, "data", "config.json")

# Ожидаемая структура config.json: раздел -> {ключ: вид значения}.
# Виды значений проверяет функция _check_value().
CONFIG_SCHEMA = {
    "network": {
        "ru_hosts": "host_list",
        "foreign_hosts": "host_list",
        "tcp_port": "port",
        "tcp_timeout_s": "positive_number",
        "ping_timeout_s": "positive_int",
    },
    "firewall_test": {
        "host": "str",
        "control_port": "port",
        "test_port": "port",
        "timeout_s": "positive_number",
    },
    "antivirus_test": {
        "eicar_dir": "str_or_null",
        "eicar_timeout_s": "positive_number",
        "poll_interval_s": "positive_number",
    },
    "report": {
        "dir": "str",
    },
}


class ConfigError(Exception):
    """Ошибка в файле настроек. Текст ошибки предназначен для пользователя."""


def _is_number(value: object) -> bool:
    """Проверить, что значение — число (int или float), но не true/false.

    В Python bool — подкласс int, поэтому без явной проверки true из JSON прошло бы
    как число 1.
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_int(value: object) -> bool:
    """Проверить, что значение — целое число, но не true/false."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_nonempty_str(value: object) -> bool:
    """Проверить, что значение — непустая строка (пробелы не считаются)."""
    return isinstance(value, str) and value.strip() != ""


def _check_value(value: object, kind: str) -> Optional[str]:
    """Проверить значение по виду из CONFIG_SCHEMA.

    Возвращает None, если значение подходит, иначе описание ожидаемого значения.
    """
    if kind == "str":
        if not _is_nonempty_str(value):
            return "ожидается непустая строка"
    elif kind == "str_or_null":
        if value is not None and not _is_nonempty_str(value):
            return "ожидается непустая строка или null"
    elif kind == "host_list":
        if not isinstance(value, list) or len(value) == 0:
            return "ожидается непустой список имён узлов"
        for item in value:
            if not _is_nonempty_str(item):
                return "каждый элемент списка должен быть непустой строкой"
    elif kind == "port":
        if not _is_int(value) or not 1 <= value <= 65535:
            return "ожидается номер порта, целое число от 1 до 65535"
    elif kind == "positive_int":
        if not _is_int(value) or value <= 0:
            return "ожидается целое число больше нуля"
    elif kind == "positive_number":
        if not _is_number(value) or value <= 0:
            return "ожидается число больше нуля"
    else:
        # Сюда попадаем только при опечатке в CONFIG_SCHEMA, то есть при ошибке в коде.
        raise ValueError("неизвестный вид значения в CONFIG_SCHEMA: " + kind)
    return None


def validate_config(config: object) -> None:
    """Проверить наличие ключей, типы значений и согласованность настроек.

    При первой найденной ошибке выбрасывает ConfigError с указанием ключа.
    Лишние ключи не считаются ошибкой.
    """
    if not isinstance(config, dict):
        raise ConfigError("корневой элемент должен быть объектом JSON ({...})")

    for section, keys in CONFIG_SCHEMA.items():
        if section not in config:
            raise ConfigError("нет раздела «{}»".format(section))
        if not isinstance(config[section], dict):
            raise ConfigError("раздел «{}» должен быть объектом JSON".format(section))
        for key, kind in keys.items():
            full_key = section + "." + key
            if key not in config[section]:
                raise ConfigError("нет ключа «{}»".format(full_key))
            value = config[section][key]
            problem = _check_value(value, kind)
            if problem is not None:
                raise ConfigError("ключ «{}»: {}, получено: {}".format(
                    full_key, problem, json.dumps(value, ensure_ascii=False)))

    # Проверки, связывающие несколько ключей.
    fw = config["firewall_test"]
    if fw["test_port"] == fw["control_port"]:
        raise ConfigError("ключи «firewall_test.test_port» и «firewall_test.control_port» "
                          "должны различаться: тестовый порт запрещён правилом МЭ, "
                          "контрольный разрешён")
    av = config["antivirus_test"]
    if av["poll_interval_s"] > av["eicar_timeout_s"]:
        raise ConfigError("ключ «antivirus_test.poll_interval_s» не может быть больше "
                          "«antivirus_test.eicar_timeout_s»")


def load_config(path: Optional[str] = None) -> dict:
    """Прочитать config.json, проверить его и вернуть настройки в виде словаря.

    path — путь к файлу; если не задан, используется DEFAULT_CONFIG_PATH.
    Любая ошибка (нет файла, неверный JSON, неверное значение) превращается
    в ConfigError с понятным текстом, в котором указан файл.
    """
    if path is None:
        path = DEFAULT_CONFIG_PATH

    try:
        with open(path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        raise ConfigError("{}: файл не найден".format(path))
    except PermissionError:
        raise ConfigError("{}: нет прав на чтение файла".format(path))
    except json.JSONDecodeError as exc:
        raise ConfigError("{}: ошибка JSON в строке {}, столбце {}: {}".format(
            path, exc.lineno, exc.colno, exc.msg))
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError("{}: не удалось прочитать файл: {}".format(path, exc))

    try:
        validate_config(config)
    except ConfigError as exc:
        raise ConfigError("{}: {}".format(path, exc))
    return config
