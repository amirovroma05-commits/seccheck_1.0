#!/usr/bin/env python3
"""SecCheck — контроль работоспособности антивируса и межсетевого экрана в Linux.

Точка входа: меню, хранение результатов проверок и вывод отчёта (модуль M5).
Запуск после установки (`sudo ./install.sh`): `sudo seccheck`. Настройки всегда
берутся из /etc/seccheck/config.json, список продуктов — из products.json рядом
с main.py.
"""

import sys

# Не создавать каталоги __pycache__: при запуске через sudo они принадлежали бы root.
# Флаг должен быть установлен до импорта модулей проекта, поэтому импорты ниже
# стоят не в начале файла.
sys.dont_write_bytecode = True

import codecs  # noqa: E402
import io  # noqa: E402

# Весь вывод программы на русском. При локали C/POSIX (sudo, cron, ssh с LANG=C)
# Python 3.5 выбирает для stdout и stderr кодировку ASCII, и первый же print
# с кириллицей упал бы с UnicodeEncodeError. Поэтому такой поток заново открывается
# в UTF-8 поверх того же двоичного буфера. Исходные объекты остаются в sys.__stdout__
# и sys.__stderr__, поэтому их буфер не будет закрыт сборщиком мусора.
if codecs.lookup(sys.stdout.encoding).name != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace",
                                  line_buffering=True)
if codecs.lookup(sys.stderr.encoding).name != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace",
                                  line_buffering=True)

import argparse  # noqa: E402
import os  # noqa: E402
import platform  # noqa: E402
import socket  # noqa: E402
from datetime import datetime  # noqa: E402
from typing import Dict, List, Tuple  # noqa: E402

import check_antivirus  # noqa: E402
import check_firewall  # noqa: E402
import check_network  # noqa: E402
import check_presence  # noqa: E402
from common import (APP_NAME, APP_VERSION, DEFAULT_CONFIG_PATH, ERROR, FAIL,  # noqa: E402
                    INCONCLUSIVE, NOT_RUN, OK, WARNING, is_root, load_config,
                    os_info)

# Файл продуктов: products.json в каталоге, где лежит main.py.
# realpath раскрывает символические ссылки, чтобы найти настоящий каталог программы.
PRODUCTS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                     "products.json")

# Код возврата, если файл настроек или продуктов не прошёл проверку.
EXIT_BAD_FILE = 2

# Настройки и список продуктов для M2 и M3. Заполняются один раз в main() до показа меню.
config = {}  # type: Dict[str, dict]
products = []  # type: List[dict]

# Подробный вывод (флаг -v). Без него у каждой проверки печатаются только краткие строки
# (итог, найденные продукты в M2, подсказки при не-OK), с ним — ещё и подробности.
verbose = False

# Тип результата проверки: (статус, краткие строки, подробности).
# Краткие строки: [результат, строки под итогом...]; подробности печатаются только с -v.
Result = Tuple[str, List[str], List[str]]


# Каждая проверка получает свою секцию настроек. Функции ниже нужны, чтобы
# в CHECKS все проверки вызывались одинаково — без аргументов.

def run_network() -> Result:
    """Запустить M1 с секцией "network"."""
    return check_network.run(config["network"])


def run_presence() -> Result:
    """Запустить M2 с секцией "presence" и загруженным списком продуктов."""
    return check_presence.run(config["presence"], products)


def run_firewall() -> Result:
    """Запустить M3 с секцией "firewall_test" и загруженным списком продуктов."""
    return check_firewall.run(config["firewall_test"], products)


def run_antivirus() -> Result:
    """Запустить M4 с секцией "antivirus_test"."""
    return check_antivirus.run(config["antivirus_test"])


# Проверки по порядку: (идентификатор, название, функция без аргументов).
# Название одно и то же в меню, в строке результата и в отчёте.
CHECKS = [
    ("M1", "Подключение к интернету", run_network),
    ("M2", "Наличие АВ и МЭ", run_presence),
    ("M3", "Работоспособность МЭ", run_firewall),
    ("M4", "Работоспособность АВ", run_antivirus),
]

# Метки статусов для вывода.
STATUS_LABELS = {
    OK: "[  OK  ]",
    WARNING: "[ WARN ]",
    FAIL: "[ FAIL ]",
    INCONCLUSIVE: "[  ??  ]",
    NOT_RUN: "[ ---- ]",
    ERROR: "[ ERR  ]",
}

# Код возврата при Ctrl+C (128 + номер сигнала SIGINT), принятый в Linux.
EXIT_INTERRUPTED = 130

# Результаты проверок: идентификатор -> (статус, краткие строки, подробности).
results = {}  # type: Dict[str, Result]

# Отступ строк под итогом: ширина метки статуса и идентификатора («[  OK  ] M1  »).
INDENT = " " * 9


def build_menu() -> str:
    """Текст меню. Пункты 1–4 берут названия из CHECKS."""
    lines = [""]
    for number, (_check_id, title, _function) in enumerate(CHECKS, start=1):
        lines.append("  {}  {}".format(number, title))
    lines.append("  5  Выполнить все проверки")
    lines.append("  6  Вывести отчёт")
    lines.append("  0  Выход")
    lines.append("")
    return "\n".join(lines)


def print_result(check_id: str, title: str, result: Result) -> None:
    """Напечатать результат: «метка Mn  Название: результат», под ним краткие строки,
    с флагом -v — ещё и подробности.
    """
    status, brief, details = result
    print("{} {}  {}: {}".format(STATUS_LABELS[status], check_id, title, brief[0]))
    for line in brief[1:]:
        print(INDENT + line)
    if verbose:
        for line in details:
            print(INDENT + line)


def run_check(index: int) -> None:
    """Выполнить проверку CHECKS[index], сохранить результат в results и напечатать его.

    Неожиданное исключение в модуле не роняет программу, а даёт статус ERROR.
    Ctrl+C (KeyboardInterrupt) не перехватывается: его обрабатывает блок
    `if __name__ == "__main__"` в конце файла. SystemExit (SIGTERM или SIGHUP во время M3)
    тоже не перехватывается: `except Exception` его не ловит, и программа завершается.
    """
    check_id, title, function = CHECKS[index]
    print("Выполняется {}: {}…".format(check_id, title))
    try:
        result = function()
    except Exception as exc:
        result = (ERROR, ["ошибка проверки ({}: {})".format(type(exc).__name__, exc)], [])
    results[check_id] = result
    print_result(check_id, title, result)
    print()


def print_report() -> None:
    """M5. Вывести отчёт: заголовок, затем результат каждой проверки в том же виде,
    что и при её запуске (с -v — вместе с подробностями).
    """
    print()
    print("Результаты тестирования средств защиты")
    print("{} {} · {}".format(APP_NAME, APP_VERSION,
                              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print("ПК: {} · {} · Python {} · запуск от root: {}".format(
        socket.gethostname(), os_info(), platform.python_version(),
        "да" if is_root() else "нет"))
    print()

    # Проверка, которой нет в results, показывается как NOT_RUN.
    for check_id, title, _function in CHECKS:
        if check_id in results:
            result = results[check_id]
        else:
            result = (NOT_RUN, ["не выполнялась"], [])
        print_result(check_id, title, result)
    print()


def print_root_warning() -> None:
    """Без прав root предупредить, какие проверки будут ограничены."""
    if not is_root():
        print("Внимание: нет прав root. Проверка M3 не выполнится: для тестового правила МЭ "
              "нужны права root.")


def menu() -> None:
    """Интерактивное меню. Возвращается при выборе 0 или конце ввода (Ctrl+D)."""
    while True:
        print(build_menu())
        try:
            choice = input("Выберите пункт: ").strip()
        except EOFError:
            print()
            return
        print()
        if choice == "0":
            return
        elif choice in ("1", "2", "3", "4"):
            run_check(int(choice) - 1)
        elif choice == "5":
            for index in range(len(CHECKS)):
                run_check(index)
        elif choice == "6":
            print_report()
        else:
            print("Нет такого пункта: «{}». Введите число от 0 до 6.".format(choice))


def main() -> int:
    """Разобрать аргументы, показать заголовок и меню. Вернуть код завершения."""
    parser = argparse.ArgumentParser(
        prog="seccheck",
        description="Контроль работоспособности антивируса и межсетевого экрана в Linux.")
    parser.add_argument("--version", action="version",
                        version="{} {}".format(APP_NAME, APP_VERSION))
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="подробный вывод: признаки, команды, время подключений")
    args = parser.parse_args()

    # Настройки и список продуктов загружаются один раз до показа меню.
    # Нет файла или в нём ошибка — программа не запускается.
    global config, products, verbose
    verbose = args.verbose
    # Текст ошибки уже содержит путь к файлу.
    try:
        config = load_config(DEFAULT_CONFIG_PATH)
        products = check_presence.load_products(PRODUCTS_PATH)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return EXIT_BAD_FILE

    print("{} {} · {} · запуск от root: {}".format(
        APP_NAME, APP_VERSION, os_info(), "да" if is_root() else "нет"))
    print_root_warning()
    menu()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Ctrl+C в любой момент: только перевод строки, чтобы приглашение терминала
        # не склеилось с выводом. Файл EICAR (M4) и тестовое правило МЭ (M3) к этому
        # моменту уже удалены в check_antivirus и check_firewall.
        print()
        sys.exit(EXIT_INTERRUPTED)
