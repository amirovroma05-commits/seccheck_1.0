"""M2. Обнаружение межсетевого экрана (МЭ) и антивируса (АВ).

В Linux нет единого реестра средств защиты, поэтому применяются два способа:
(а) поиск известных продуктов из списка products.json по службам systemd и файлам;
(б) универсальная проверка: есть ли запрещающие правила в netfilter, через который
работают практически все сетевые фильтры Linux.

Файл продуктов читает программа с правами root, поэтому в его формате нет полей
с командами: имена служб передаются в systemctl отдельным аргументом через run_cmd,
пути проверяются только через os.path.exists.
"""

import json
import os
import re
from collections import OrderedDict
from typing import List, Tuple

from common import BRIEF_PREFIX, FAIL, OK, WARNING, check_netfilter, is_root, run_cmd

# Настройки берутся из секции "presence" файла настроек (см. README.md, «Настройки»):
#   cmd_timeout_s — таймаут одной внешней команды (systemctl, nft, iptables), с.

# Уровни обнаружения продукта (чем больше число, тем выше уровень).
NOT_FOUND = 0          # признаков нет
INSTALLED = 1          # есть файл продукта
RUNNING = 2            # служба продукта активна
ACTIVE = 3             # подтверждено, что защита включена

LEVEL_NAMES = {
    NOT_FOUND: "не найден",
    INSTALLED: "установлен",
    RUNNING: "служба запущена",
    ACTIVE: "защита активна",
}

# Поля продукта в products.json: имя поля -> обязательно ли оно.
#   id                  — уникальный идентификатор;
#   name                — название для отчёта;
#   kinds               — "antivirus" и/или "firewall";
#   services            — службы systemd: любая активная -> RUNNING;
#   files               — файлы: любой существующий -> INSTALLED;
#   protection_service  — служба резидентной защиты АВ: активна -> ACTIVE;
#   active_if_filtering — ACTIVE, если служба продукта активна и netfilter фильтрует;
#   verified            — имена служб и пути проверены на реальной системе;
#   notes               — примечание (в отчёт не выводится).
# Без protection_service и active_if_filtering максимальный уровень продукта — RUNNING.
# OrderedDict: в Python 3.5 обычный словарь не сохраняет порядок, а от порядка зависит,
# какое отсутствующее поле будет названо в сообщении об ошибке первым.
PRODUCT_FIELDS = OrderedDict([
    ("id", True),
    ("name", True),
    ("kinds", True),
    ("services", True),
    ("files", True),
    ("protection_service", False),
    ("active_if_filtering", False),
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

    protection = item.get("protection_service")
    if protection is not None and not is_service_name(protection):
        raise ValueError('поле "protection_service": недопустимое имя службы {} '
                         '(ожидается имя службы или null)'.format(show(protection)))

    for field in ("active_if_filtering", "verified"):
        if field in item and not isinstance(item[field], bool):
            raise ValueError("поле {} должно быть true или false".format(show(field)))

    if "notes" in item and not isinstance(item["notes"], str):
        raise ValueError('поле "notes" должно быть строкой')

    # Значения по умолчанию для необязательных полей.
    product = dict(item)
    product.setdefault("protection_service", None)
    product.setdefault("active_if_filtering", False)
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


def service_active(name: str, timeout_s: float) -> bool:
    """Активна ли служба systemd (`systemctl is-active` печатает «active»)."""
    code, stdout, _stderr = run_cmd(["systemctl", "is-active", name], timeout=timeout_s)
    return code == 0 and stdout.strip() == "active"


def detect_product(product: dict, timeout_s: float) -> Tuple[int, List[str]]:
    """Шаг 3. Определить уровень продукта по файлам и службам. Вернуть (уровень, признаки)."""
    level = NOT_FOUND
    evidence = []
    for path in product["files"]:
        if os.path.exists(path):
            level = INSTALLED
            evidence.append("файл " + path)
    for service in product["services"]:
        if service_active(service, timeout_s):
            level = RUNNING
            evidence.append("служба {} активна".format(service))
    return level, evidence


def run(cfg: dict, products: List[dict]) -> Tuple[str, List[str]]:
    """Выполнить проверку M2. Вернуть (статус, [итог, подробности...]).

    cfg — секция "presence" файла настроек;
    products — список продуктов, загруженный load_products() при старте программы.
    """
    # Шаг 1. Netfilter проверяем первым: от него зависит уровень МЭ.
    timeout_s = cfg["cmd_timeout_s"]
    filtering, netfilter_details, netfilter_read = check_netfilter(timeout_s)

    found = []  # список (продукт, уровень)
    brief = []  # строки найденных продуктов для краткого вывода
    details = []
    # Шаги 2–6. Перебор продуктов.
    for product in products:
        level, evidence = detect_product(product, timeout_s)
        if level == NOT_FOUND:
            # Непроверенный профиль может не найти продукт из-за неверных имён служб
            # и путей, поэтому только здесь пометка о том, что профиль не проверен.
            if not product["verified"]:
                details.append("{}: не найден (профиль не проверен на стенде)".format(
                    product["name"]))
            continue
        # Шаг 5. Проверка активности защиты.
        protection = product["protection_service"]
        if protection is not None and service_active(protection, timeout_s):
            level = ACTIVE
            evidence.append("служба защиты {} активна".format(protection))
        if product["active_if_filtering"] and level == RUNNING and filtering:
            level = ACTIVE
            evidence.append("netfilter фильтрует трафик")
        found.append((product, level))
        # Найденный продукт подтверждает свои имена на этой системе, поэтому пометки
        # «профиль не проверен» у него нет.
        brief.append("{}{} — {}".format(BRIEF_PREFIX, product["name"], LEVEL_NAMES[level]))
        details.append("{}: {}".format(product["name"], ", ".join(evidence)))

    details.extend(netfilter_details)
    if not netfilter_read and not is_root():
        details.append("Правила МЭ не прочитаны: нужны права root")

    # Шаг 7. Итоговый статус.
    av_present = False
    av_active = False
    fw_present = False
    fw_active = False
    for product, level in found:
        if "antivirus" in product["kinds"]:
            av_present = True
            if level == ACTIVE:
                av_active = True
        if "firewall" in product["kinds"]:
            fw_present = True
            if level == ACTIVE:
                fw_active = True

    # Краткие строки продуктов идут первыми, за ними подробности.
    details = brief + details
    if av_active and (fw_active or filtering):
        summary = "МЭ и АВ обнаружены, защита активна"
        if filtering:
            summary += "; фильтрация netfilter включена"
        return OK, [summary] + details
    if not av_present and not fw_present and not filtering:
        return FAIL, ["МЭ и АВ не обнаружены, фильтрации netfilter нет"] + details

    missing = []
    if not av_present:
        missing.append("АВ не обнаружен")
    elif not av_active:
        missing.append("резидентная защита АВ не подтверждена")
    if not fw_present and not filtering:
        missing.append("МЭ не обнаружен и фильтрации нет")
    elif not fw_active and not filtering:
        missing.append("МЭ найден, но фильтрация не подтверждена")
    return WARNING, ["; ".join(missing)] + details
