"""M2. Обнаружение межсетевого экрана (МЭ) и антивируса (АВ).

В Linux нет единого реестра средств защиты, поэтому применяются два способа:
(а) поиск известных продуктов из списка PRODUCTS по службам systemd и файлам;
(б) универсальная проверка: есть ли запрещающие правила в netfilter, через который
работают практически все сетевые фильтры Linux.
"""

from __future__ import annotations

import os
from typing import List, Tuple

from common import CMD_NOT_FOUND, FAIL, OK, WARNING, is_root, run_cmd

# Таймаут одной внешней команды (systemctl, nft, iptables), с.
CMD_TIMEOUT_S = 5

# Уровни обнаружения продукта (чем больше число, тем выше уровень).
NOT_FOUND = 0          # признаков нет
INSTALLED = 1          # есть файл продукта
RUNNING = 2            # служба продукта активна
ACTIVE = 3             # подтверждено, что защита включена

LEVEL_NAMES = {
    NOT_FOUND: "не найден",
    INSTALLED: "установлен",
    RUNNING: "работает",
    ACTIVE: "защита активна",
}

# Известные продукты.
#   kinds              — "antivirus" и/или "firewall";
#   services           — службы systemd: любая активная -> RUNNING;
#   paths              — файлы: любой существующий -> INSTALLED;
#   protection_service — служба резидентной защиты АВ: активна -> ACTIVE;
#   needs_filtering    — для МЭ: ACTIVE, если служба активна и netfilter фильтрует.
# Если ни protection_service, ни needs_filtering нет, максимальный уровень — RUNNING.
PRODUCTS = [
    {
        "name": "ClamAV",
        "kinds": ["antivirus"],
        "services": ["clamav-daemon"],
        "paths": ["/usr/sbin/clamd"],
        # TODO(стенд): проверить имя службы clamonacc в используемом дистрибутиве.
        "protection_service": "clamav-clamonacc",
        "needs_filtering": False,
    },
    {
        "name": "ufw",
        "kinds": ["firewall"],
        "services": ["ufw"],
        "paths": ["/usr/sbin/ufw"],
        "protection_service": None,
        "needs_filtering": True,
    },
    {
        # Имена не проверены на стенде: взяты из документации производителя.
        "name": "Dr.Web для Linux",
        "kinds": ["antivirus", "firewall"],
        "services": ["drweb-configd"],
        "paths": ["/opt/drweb.com/bin/drweb-ctl"],
        "protection_service": None,
        "needs_filtering": False,
    },
    {
        # Имена не проверены на стенде: взяты из документации производителя.
        "name": "Kaspersky Endpoint Security для Linux",
        "kinds": ["antivirus", "firewall"],
        "services": ["kesl"],
        "paths": ["/opt/kaspersky/kesl/bin/kesl-control"],
        "protection_service": None,
        "needs_filtering": False,
    },
]

# Команды, выводящие правила netfilter. Правила iptables-legacy не видны через nft,
# поэтому смотрим все источники.
NETFILTER_COMMANDS = [
    ["nft", "list", "ruleset"],
    ["iptables", "-S"],
    ["iptables-legacy", "-S"],
]


def service_active(name: str) -> bool:
    """Активна ли служба systemd (`systemctl is-active` печатает «active»)."""
    code, stdout, _stderr = run_cmd(["systemctl", "is-active", name], timeout=CMD_TIMEOUT_S)
    return code == 0 and stdout.strip() == "active"


def check_netfilter() -> Tuple[bool, List[str], bool]:
    """Шаг 1. Проверить правила netfilter.

    Вернуть (фильтрация включена, подробности, удалось ли прочитать хоть один источник).
    Фильтрация считается включённой, если в выводе есть drop или reject
    (без учёта регистра).
    """
    filtering = False
    any_read = False
    details = []
    for cmd in NETFILTER_COMMANDS:
        command_text = " ".join(cmd)
        code, stdout, stderr = run_cmd(cmd, timeout=CMD_TIMEOUT_S)
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
        text = stdout.lower()
        if "drop" in text or "reject" in text:
            filtering = True
            details.append("{}: есть запрещающие правила (drop/reject)".format(command_text))
        else:
            details.append("{}: запрещающих правил нет".format(command_text))
    return filtering, details, any_read


def detect_product(product: dict) -> Tuple[int, List[str]]:
    """Шаг 3. Определить уровень продукта по файлам и службам. Вернуть (уровень, признаки)."""
    level = NOT_FOUND
    evidence = []
    for path in product["paths"]:
        if os.path.exists(path):
            level = INSTALLED
            evidence.append("файл " + path)
    for service in product["services"]:
        if service_active(service):
            level = RUNNING
            evidence.append("служба {} активна".format(service))
    return level, evidence


def run() -> Tuple[str, List[str]]:
    """Выполнить проверку M2. Вернуть (статус, [итог, подробности...])."""
    # Шаг 1. Netfilter проверяем первым: от него зависит уровень МЭ.
    filtering, netfilter_details, netfilter_read = check_netfilter()

    found = []  # список (продукт, уровень)
    details = []
    # Шаги 2–6. Перебор продуктов.
    for product in PRODUCTS:
        level, evidence = detect_product(product)
        if level == NOT_FOUND:
            continue
        # Шаг 5. Проверка активности защиты.
        protection = product["protection_service"]
        if protection is not None and service_active(protection):
            level = ACTIVE
            evidence.append("служба защиты {} активна".format(protection))
        if product["needs_filtering"] and level == RUNNING and filtering:
            level = ACTIVE
            evidence.append("netfilter фильтрует трафик")
        found.append((product, level))
        details.append("{}: {} ({})".format(product["name"], LEVEL_NAMES[level],
                                            ", ".join(evidence)))

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

    summary_parts = []
    for product, level in found:
        summary_parts.append("{} — {}".format(product["name"], LEVEL_NAMES[level]))
    if filtering:
        summary_parts.append("фильтрация netfilter включена")

    if av_active and (fw_active or filtering):
        return OK, ["МЭ и АВ: " + "; ".join(summary_parts)] + details
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
