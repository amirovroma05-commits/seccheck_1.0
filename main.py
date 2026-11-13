#!/usr/bin/env python3
"""SecCheck — контроль работоспособности антивируса и межсетевого экрана в Linux.

Точка входа: меню, хранение результатов проверок и вывод отчёта (модуль M5).
Запуск: `sudo ./main.py` или, после установки, `sudo seccheck`.
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
from common import (APP_NAME, APP_VERSION, DEFAULT_CONFIG_PATH, ERROR,  # noqa: E402
                    FAIL, INCONCLUSIVE, NOT_RUN, OK, WARNING, is_root, load_config,
                    os_info)

# Файл продуктов по умолчанию: products.json в каталоге, где лежит main.py.
# realpath раскрывает символические ссылки, чтобы найти настоящий каталог программы.
DEFAULT_PRODUCTS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                     "products.json")

# Код возврата, если файл настроек или продуктов не прошёл проверку.
EXIT_BAD_FILE = 2

# Настройки, список продуктов для M2 и пути к файлам, из которых они загружены.
# Заполняются один раз в main() до показа меню.
config = {}  # type: Dict[str, dict]
config_path = ""
products = []  # type: List[dict]
products_path = ""


# Каждая проверка получает свою секцию настроек. Функции ниже нужны, чтобы
# в CHECKS все проверки вызывались одинаково — без аргументов.

def run_network() -> Tuple[str, List[str]]:
    """Запустить M1 с секцией "network"."""
    return check_network.run(config["network"])


def run_presence() -> Tuple[str, List[str]]:
    """Запустить M2 с секцией "presence" и загруженным списком продуктов."""
    return check_presence.run(config["presence"], products)


def run_firewall() -> Tuple[str, List[str]]:
    """Запустить M3 с секцией "firewall_test"."""
    return check_firewall.run(config["firewall_test"])


def run_antivirus() -> Tuple[str, List[str]]:
    """Запустить M4 с секцией "antivirus_test"."""
    return check_antivirus.run(config["antivirus_test"])


# Проверки по порядку: (идентификатор, название, функция без аргументов).
CHECKS = [
    ("M1", "Подключение к интернету", run_network),
    ("M2", "Наличие МЭ и АВ", run_presence),
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

MENU = """
  1  Проверка подключения к интернету
  2  Проверка наличия МЭ и АВ
  3  Проверка работоспособности МЭ
  4  Проверка работоспособности АВ
  5  Выполнить все проверки
  6  Вывести отчёт
  0  Выход
"""

# Код возврата при Ctrl+C (128 + номер сигнала SIGINT), принятый в Linux.
EXIT_INTERRUPTED = 130

# Результаты проверок: идентификатор -> (статус, [итог, подробности...]).
results = {}  # type: Dict[str, Tuple[str, List[str]]]


def print_result(check_id: str, status: str, lines: List[str]) -> None:
    """Напечатать результат проверки: метка, итог, затем подробности с отступом."""
    print("{} {}  {}".format(STATUS_LABELS[status], check_id, lines[0]))
    for line in lines[1:]:
        print("         " + line)


def run_check(index: int) -> None:
    """Выполнить проверку CHECKS[index], сохранить результат в results и напечатать его.

    Неожиданное исключение в модуле не роняет программу, а даёт статус ERROR.
    Ctrl+C (KeyboardInterrupt) не перехватывается: его обрабатывает main().
    """
    check_id, title, function = CHECKS[index]
    print("Выполняется {}: {}…".format(check_id, title))
    try:
        status, lines = function()
    except Exception as exc:
        status = ERROR
        lines = ["Сбой программы при выполнении проверки",
                 "{}: {}".format(type(exc).__name__, exc)]
    results[check_id] = (status, lines)
    print_result(check_id, status, lines)
    print()


def print_report() -> None:
    """M5. Вывести отчёт: заголовок, итог по каждой проверке, затем подробности."""
    print()
    print("Результаты тестирования средств защиты")
    print("{} {} · {}".format(APP_NAME, APP_VERSION,
                              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print("ПК: {} · {} · Python {} · запуск от root: {}".format(
        socket.gethostname(), os_info(), platform.python_version(),
        "да" if is_root() else "нет"))
    print("Файл настроек: " + config_path)
    print("Файл продуктов: " + products_path)
    print()

    # Проверка, которой нет в results, показывается как NOT_RUN.
    report = []
    for check_id, title, _function in CHECKS:
        if check_id in results:
            status, lines = results[check_id]
        else:
            status, lines = NOT_RUN, [title + ": не выполнялась"]
        report.append((check_id, title, status, lines))

    for number, (check_id, title, status, lines) in enumerate(report, start=1):
        print("{}. {} {}".format(number, STATUS_LABELS[status], lines[0]))

    print()
    print("Подробности")
    for check_id, title, status, lines in report:
        print()
        print_result(check_id, status, lines)
    print()


def print_root_warning() -> None:
    """Без прав root предупредить, какие проверки будут ограничены."""
    if not is_root():
        print("Внимание: нет прав root. Ограничена проверка M2: правила МЭ "
              "(nft, iptables) не будут прочитаны.")


def menu() -> None:
    """Интерактивное меню. Возвращается при выборе 0 или конце ввода (Ctrl+D)."""
    while True:
        print(MENU)
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
    parser.add_argument("--config", metavar="PATH", default=DEFAULT_CONFIG_PATH,
                        help="файл настроек (по умолчанию {})".format(DEFAULT_CONFIG_PATH))
    parser.add_argument("--products", metavar="PATH", default=DEFAULT_PRODUCTS_PATH,
                        help="файл со списком продуктов для M2 "
                             "(по умолчанию products.json рядом с main.py)")
    args = parser.parse_args()

    # Настройки и список продуктов загружаются один раз до показа меню.
    # Нет файла или в нём ошибка — программа не запускается.
    global config, config_path, products, products_path
    config_path = os.path.abspath(args.config)
    try:
        config = load_config(config_path)
    except ValueError as exc:
        # Текст ошибки уже содержит путь к файлу и подсказку.
        print(exc, file=sys.stderr)
        return EXIT_BAD_FILE

    products_path = os.path.abspath(args.products)
    try:
        products = check_presence.load_products(products_path)
    except ValueError as exc:
        print("Ошибка в файле продуктов: {}".format(exc), file=sys.stderr)
        return EXIT_BAD_FILE

    print("{} {} · {} · запуск от root: {}".format(
        APP_NAME, APP_VERSION, os_info(), "да" if is_root() else "нет"))
    print_root_warning()
    try:
        menu()
    except KeyboardInterrupt:
        # Файл EICAR к этому моменту уже удалён блоком finally в check_antivirus.
        print()
        print("Прервано пользователем.")
        return EXIT_INTERRUPTED
    return 0


if __name__ == "__main__":
    sys.exit(main())
