#!/usr/bin/env python3
"""SecCheck — контроль работоспособности антивируса и межсетевого экрана в Linux.

Точка входа: меню, хранение результатов проверок и вывод отчёта (модуль M5).
Запуск: `sudo ./main.py` или, после установки, `sudo seccheck`.
"""

from __future__ import annotations

import sys

# Не создавать каталоги __pycache__: при запуске через sudo они принадлежали бы root.
# Флаг должен быть установлен до импорта модулей проекта, поэтому импорты ниже
# стоят не в начале файла.
sys.dont_write_bytecode = True

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
from common import (APP_NAME, APP_VERSION, ERROR, FAIL, INCONCLUSIVE,  # noqa: E402
                    NOT_RUN, OK, WARNING, is_root, os_info)

# Файл продуктов по умолчанию: products.json в каталоге, где лежит main.py.
# realpath раскрывает символические ссылки, чтобы найти настоящий каталог программы.
DEFAULT_PRODUCTS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                     "products.json")

# Код возврата, если файл продуктов не прошёл проверку.
EXIT_BAD_PRODUCTS = 2

# Список продуктов для M2 и путь к файлу, из которого он загружен.
# Заполняются один раз в main() до показа меню.
products: List[dict] = []
products_path = ""


def run_presence() -> Tuple[str, List[str]]:
    """Запустить M2 с загруженным списком продуктов."""
    return check_presence.run(products)


# Проверки по порядку: (идентификатор, название, функция без аргументов).
CHECKS = [
    ("M1", "Подключение к интернету", check_network.run),
    ("M2", "Наличие МЭ и АВ", run_presence),
    ("M3", "Работоспособность МЭ", check_firewall.run),
    ("M4", "Работоспособность АВ", check_antivirus.run),
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
results: Dict[str, Tuple[str, List[str]]] = {}


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
    parser.add_argument("--products", metavar="PATH", default=DEFAULT_PRODUCTS_PATH,
                        help="файл со списком продуктов для M2 "
                             "(по умолчанию products.json рядом с main.py)")
    args = parser.parse_args()

    # Список продуктов загружается один раз до показа меню.
    # Битый файл — программа не запускается.
    global products, products_path
    products_path = os.path.abspath(args.products)
    try:
        products = check_presence.load_products(products_path)
    except ValueError as exc:
        print("Ошибка в файле продуктов: {}".format(exc), file=sys.stderr)
        return EXIT_BAD_PRODUCTS

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
