"""M2. Обнаружение антивируса (АВ) и межсетевого экрана (МЭ).

Отвечает только на вопрос: есть ли в системе АВ и МЭ. Работают ли они, проверяют M3 и M4.

В Linux нет единого реестра средств защиты, поэтому известные продукты ищутся по описаниям
из файла products.json: по файлам и службам systemd. Продукт найден, если есть хотя бы
один его файл или установлена хотя бы одна его служба.

Файл продуктов читает программа с правами root, поэтому в его формате нет полей
с командами: имена служб передаются в systemctl отдельным аргументом через run_cmd,
пути проверяются только через os.path.exists.
"""

import json
import os
import re
from collections import OrderedDict
from typing import List, Tuple

from common import FAIL, OK, WARNING, run_cmd

# Настройки берутся из секции "presence" файла настроек (см. README.md, «Настройки»):
#   cmd_timeout_s — таймаут одной команды systemctl, с.

# Состояния службы systemd (для подробностей и пометки «служба остановлена»).
SERVICE_RUNNING = "запущена"
SERVICE_STOPPED = "остановлена"
SERVICE_NOT_INSTALLED = "не установлена"
SERVICE_UNKNOWN = "состояние неизвестно"

# Поля продукта в products.json: имя поля -> обязательно ли оно.
#   id       — уникальный идентификатор;
#   name     — название для отчёта;
#   kinds    — "antivirus" и/или "firewall";
#   services — службы systemd: любая установленная -> продукт найден;
#   files    — файлы: любой существующий -> продукт найден;
#   verified — имена служб и пути проверены на реальной системе;
#   notes    — примечание (в отчёт не выводится).
# OrderedDict: в Python 3.5 обычный словарь не сохраняет порядок, а от порядка зависит,
# какое отсутствующее поле будет названо в сообщении об ошибке первым.
PRODUCT_FIELDS = OrderedDict([
    ("id", True),
    ("name", True),
    ("kinds", True),
    ("services", True),
    ("files", True),
    ("verified", False),
    ("notes", False),
])

KNOWN_KINDS = ["antivirus", "firewall"]

# Допустимое имя службы systemd. Первый символ — буква или цифра, поэтому имя
# не может начинаться с «-» и не будет принято systemctl за ключ командной строки.
# Используется re.fullmatch: «$» в re.match пропустил бы перевод строки в конце имени.
SERVICE_NAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9@._-]*"

def show(value: object) -> str:
    """Значение из файла для сообщения об ошибке.

    json.dumps берёт строку в кавычки и экранирует управляющие символы, поэтому
    содержимое файла не может испортить вывод в терминале.
    """
    return json.dumps(value, ensure_ascii=False)


def is_service_name(value: object) -> bool:
    """Является ли значение допустимым именем службы systemd."""
    return isinstance(value, str) and re.fullmatch(SERVICE_NAME_PATTERN, value) is not None


def is_string_list(value: object) -> bool:
    """Является ли значение списком строк (возможно, пустым)."""
    if not isinstance(value, list):
        return False
    for item in value:
        if not isinstance(item, str):
            return False
    return True


def check_product(item: object) -> dict:
    """Проверить описание одного продукта и вернуть его с заполненными значениями
    по умолчанию. При ошибке выбросить ValueError с описанием (без номера продукта).
    """
    if not isinstance(item, dict):
        raise ValueError("ожидается объект {...}, получено " + show(item))

    # Неизвестные поля — ошибка: так ловятся опечатки в именах полей.
    for field in item:
        if field not in PRODUCT_FIELDS:
            raise ValueError("неизвестное поле " + show(field))
    for field, required in PRODUCT_FIELDS.items():
        if required and field not in item:
            raise ValueError("нет обязательного поля " + show(field))

    for field in ("id", "name"):
        if not isinstance(item[field], str) or item[field].strip() == "":
            raise ValueError("поле {} должно быть непустой строкой".format(show(field)))

    kinds = item["kinds"]
    if not is_string_list(kinds) or len(kinds) == 0:
        raise ValueError('поле "kinds" должно быть непустым списком из "antivirus", '
                         '"firewall"')
    for kind in kinds:
        if kind not in KNOWN_KINDS:
            raise ValueError('поле "kinds": неизвестный вид {} (допустимы "antivirus", '
                             '"firewall")'.format(show(kind)))

    if not is_string_list(item["services"]):
        raise ValueError('поле "services" должно быть списком строк')
    for service in item["services"]:
        if not is_service_name(service):
            raise ValueError('поле "services": недопустимое имя службы {} (латинские буквы, '
                             'цифры, @ . _ -; первый символ — буква или цифра)'
                             .format(show(service)))

    if not is_string_list(item["files"]):
        raise ValueError('поле "files" должно быть списком строк')
    for path in item["files"]:
        if not path.startswith("/"):
            raise ValueError('поле "files": путь {} должен быть абсолютным (начинаться '
                             'с «/»)'.format(show(path)))

    if "verified" in item and not isinstance(item["verified"], bool):
        raise ValueError('поле "verified" должно быть true или false')

    if "notes" in item and not isinstance(item["notes"], str):
        raise ValueError('поле "notes" должно быть строкой')

    # Значения по умолчанию для необязательных полей.
    product = dict(item)
    product.setdefault("verified", False)
    product.setdefault("notes", "")
    return product


def load_products(path: str) -> List[dict]:
    """Прочитать и проверить файл продуктов. Вернуть список словарей продуктов.

    Любая ошибка (нет файла, неверный JSON, неверное поле, повтор id) превращается
    в ValueError с текстом вида «путь: продукт №3 (id=kesl): что не так».
    """
    try:
        with open(path, "r", encoding="utf-8") as products_file:
            # object_pairs_hook=OrderedDict сохраняет порядок полей, как в файле: тогда
            # первым в сообщении об ошибке будет названо первое неверное поле продукта.
            data = json.load(products_file, object_pairs_hook=OrderedDict)
    except json.JSONDecodeError as exc:
        raise ValueError("{}: ошибка JSON в строке {}, столбце {}: {}".format(
            path, exc.lineno, exc.colno, exc.msg))
    except UnicodeDecodeError:
        raise ValueError("{}: файл не в кодировке UTF-8".format(path))
    except OSError as exc:
        raise ValueError("{}: не удалось прочитать файл: {}".format(path, exc.strerror))

    if not isinstance(data, dict):
        raise ValueError('{}: ожидается объект {{"products": [...]}}'.format(path))
    for field in data:
        if field != "products":
            raise ValueError("{}: неизвестное поле верхнего уровня {}".format(path, show(field)))
    if "products" not in data or not isinstance(data["products"], list):
        raise ValueError('{}: поле "products" должно быть списком'.format(path))

    products = []
    seen_ids = []
    for number, item in enumerate(data["products"], start=1):
        # id для сообщения об ошибке, если его удаётся прочитать.
        product_id = "?"
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            product_id = item["id"]
        prefix = "{}: продукт №{} (id={})".format(path, number, product_id)

        try:
            product = check_product(item)
        except ValueError as exc:
            raise ValueError("{}: {}".format(prefix, exc))
        if product["id"] in seen_ids:
            raise ValueError("{}: id повторяется (уже был у другого продукта)".format(prefix))
        seen_ids.append(product["id"])
        products.append(product)
    return products


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
            # Шаг 4. Непроверенный профиль мог не найти продукт из-за неверных имён служб
            # и путей, поэтому пометка «профиль не проверен» — только у ненайденных.
            # Признаки здесь возможны только вида «служба X: состояние неизвестно».
            line = product["name"] + ": не найден"
            if not product["verified"]:
                line += " (профиль не проверен на стенде)"
            if evidence or not product["verified"]:
                details.append(line)
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
