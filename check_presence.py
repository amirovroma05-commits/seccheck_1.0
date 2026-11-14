"""M2. Обнаружение антивируса (АВ) и межсетевого экрана (МЭ).

Отвечает только на вопрос: есть ли в системе АВ и МЭ. Работают ли они, проверяют M3 и M4.

В Linux нет единого реестра средств защиты, поэтому известные продукты ищутся по описаниям
из файла products.json: по файлам и службам systemd. Продукт найден, если есть хотя бы
один его файл или установлена хотя бы одна его служба.

Файл продуктов читает программа с правами root, поэтому в его формате нет полей
с командами: имена служб передаются в systemctl отдельным аргументом через run_cmd,
пути проверяются только через os.path.exists.
"""

import os
import re
from typing import List, Tuple

from common import FAIL, OK, WARNING, load_json, run_cmd

# Настройки берутся из секции "presence" файла настроек (см. README.md, «Настройки»):
#   cmd_timeout_s — таймаут одной команды systemctl, с.

# Состояния службы systemd (для подробностей и пометки «служба остановлена»).
SERVICE_RUNNING = "запущена"
SERVICE_STOPPED = "остановлена"
SERVICE_NOT_INSTALLED = "не установлена"
SERVICE_UNKNOWN = "состояние неизвестно"

# Поля продукта в products.json (другие поля игнорируются):
#   id       — идентификатор (по нему M3 выбирает команды тестового правила МЭ);
#   name     — название для отчёта;
#   kinds    — "antivirus" и/или "firewall";
#   services — службы systemd: любая установленная -> продукт найден;
#   files    — абсолютные пути: любой существующий файл -> продукт найден.

KNOWN_KINDS = ["antivirus", "firewall"]

# Допустимое имя службы systemd. Первый символ — буква или цифра, поэтому имя
# не может начинаться с «-» и не будет принято systemctl за ключ командной строки.
# Используется re.fullmatch: «$» в re.match пропустил бы перевод строки в конце имени.
SERVICE_NAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9@._-]*"


def is_service_name(value: object) -> bool:
    """Является ли значение допустимым именем службы systemd."""
    return isinstance(value, str) and re.fullmatch(SERVICE_NAME_PATTERN, value) is not None


def check_product(item: object) -> bool:
    """Подходит ли описание одного продукта под формат products.json.

    Защитные проверки: имя службы должно подходить под SERVICE_NAME_PATTERN, чтобы
    systemctl не принял его за ключ командной строки; пути должны быть абсолютными.
    """
    if not isinstance(item, dict):
        return False
    for field in ("id", "name"):
        if not isinstance(item.get(field), str) or item[field].strip() == "":
            return False
    kinds = item.get("kinds")
    if not isinstance(kinds, list) or len(kinds) == 0:
        return False
    for kind in kinds:
        if kind not in KNOWN_KINDS:
            return False
    services = item.get("services")
    if not isinstance(services, list):
        return False
    for service in services:
        if not is_service_name(service):
            return False
    files = item.get("files")
    if not isinstance(files, list):
        return False
    for path in files:
        if not isinstance(path, str) or not path.startswith("/"):
            return False
    return True


def load_products(path: str) -> List[dict]:
    """Прочитать и проверить файл продуктов. Вернуть список словарей продуктов.

    Любая ошибка — ValueError с одним сообщением: «путь: некорректный продукт №N»
    (или общее сообщение load_json, если файл не прочитан).
    """
    data = load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("products"), list):
        raise ValueError('{}: ожидается объект {{"products": [...]}}'.format(path))
    for number, item in enumerate(data["products"], start=1):
        if not check_product(item):
            raise ValueError("{}: некорректный продукт №{}".format(path, number))
    return data["products"]


def service_state(name: str, timeout_s: float) -> str:
    """Состояние службы systemd: SERVICE_RUNNING, SERVICE_STOPPED, SERVICE_NOT_INSTALLED
    или SERVICE_UNKNOWN (systemctl не выполнился).

    `systemctl show -p LoadState -p ActiveState <имя>` печатает строки «ключ=значение».
    LoadState=not-found — такой службы нет; ActiveState=active — служба запущена.
    `systemctl is-active` не подходит: про несуществующую и остановленную службу он
    одинаково отвечает «inactive».
    """
    # TODO(стенд): подтвердить вывод `systemctl show -p LoadState -p ActiveState` для
    # запущенной, остановленной и несуществующей службы.
    code, stdout, _stderr = run_cmd(
        ["systemctl", "show", "-p", "LoadState", "-p", "ActiveState", name],
        timeout=timeout_s)
    if code != 0:
        return SERVICE_UNKNOWN
    values = {}
    for line in stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip()
    if values.get("LoadState", "not-found") == "not-found":
        return SERVICE_NOT_INSTALLED
    if values.get("ActiveState") == "active":
        return SERVICE_RUNNING
    return SERVICE_STOPPED


def detect_product(product: dict, timeout_s: float) -> Tuple[bool, bool, List[str]]:
    """Шаг 2. Найти продукт по файлам и службам.

    Вернуть (найден ли, остановлены ли все его установленные службы, признаки).
    Признаки — найденные файлы и службы с состоянием, для подробностей.
    """
    found = False
    service_installed = False
    service_running = False
    evidence = []
    for path in product["files"]:
        if os.path.exists(path):
            found = True
            evidence.append("файл " + path)
    for service in product["services"]:
        state = service_state(service, timeout_s)
        if state == SERVICE_NOT_INSTALLED:
            continue
        if state == SERVICE_UNKNOWN:
            evidence.append("служба {}: {}".format(service, state))
        else:
            evidence.append("служба {} {}".format(service, state))  # «служба ufw запущена»
        if state == SERVICE_RUNNING:
            found = True
            service_installed = True
            service_running = True
        elif state == SERVICE_STOPPED:
            found = True
            service_installed = True
    stopped = service_installed and not service_running
    return found, stopped, evidence


def names_line(label: str, names: List[str]) -> str:
    """Строка вида «Антивирус:          ClamAV, Dr.Web для Linux» (или «не найден»)."""
    if names:
        text = ", ".join(names)
    else:
        text = "не найден"
    return "{:<20}{}".format(label, text)


def run(cfg: dict, products: List[dict]) -> Tuple[str, List[str], List[str]]:
    """Выполнить проверку M2. Вернуть (статус, краткие строки, подробности).

    cfg — секция "presence" файла настроек;
    products — список продуктов, загруженный load_products() при старте программы.
    """
    timeout_s = cfg["cmd_timeout_s"]
    antiviruses = []  # названия найденных АВ для краткой строки
    firewalls = []    # названия найденных МЭ для краткой строки
    details = []

    # Шаги 1–5. Перебор продуктов.
    for product in products:
        found, stopped, evidence = detect_product(product, timeout_s)
        if not found:
            # Шаг 4. Ненайденный продукт показывается, только если по нему есть признаки.
            # Здесь они возможны только вида «служба X: состояние неизвестно».
            if evidence:
                details.append(product["name"] + ": не найден")
            for item in evidence:
                details.append("  " + item)
            continue
        # Шаг 3. Продукт с двумя видами попадает в обе строки.
        name = product["name"]
        if stopped:
            name += " (служба остановлена)"
        if "antivirus" in product["kinds"]:
            antiviruses.append(name)
        if "firewall" in product["kinds"]:
            firewalls.append(name)
        details.append("{}: {}".format(product["name"], "; ".join(evidence)))

    # Шаг 6. Итоговый статус.
    brief_lines = [names_line("Антивирус:", antiviruses),
                   names_line("Межсетевой экран:", firewalls)]
    if antiviruses and firewalls:
        return OK, ["найдены"] + brief_lines, details
    if antiviruses:
        return WARNING, ["найден только антивирус"] + brief_lines, details
    if firewalls:
        return WARNING, ["найден только межсетевой экран"] + brief_lines, details
    return FAIL, ["не найдены"] + brief_lines, details
