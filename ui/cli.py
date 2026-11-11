"""Консольный интерфейс SecCheck: разбор аргументов и интерактивное меню.

Этап 1: меню-заглушка. Пункты 1–4 вызывают контроллер (пока проверки возвращают
«не реализована»), пункт 6 и флаги --all, --check, --json, --no-color, --print-fw-rule
добавятся на следующих этапах. Цветной вывод результатов появится в ui/render.py.
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable, List, Optional

from adapters.base import SystemAdapter
from adapters.factory import UnsupportedPlatformError, create_adapter
from core import APP_NAME, APP_VERSION
from core.config import ConfigError, load_config
from core.controller import Controller
from core.models import CheckResult
from core.store import ResultStore

# Код возврата при Ctrl+C (128 + номер сигнала SIGINT), принятый в Linux.
EXIT_INTERRUPTED = 130
# Код возврата при сбое запуска (ошибка конфигурации, неподдерживаемая ОС).
EXIT_ERROR = 3

# Пункты меню: (клавиша, текст, идентификатор проверки или None).
MENU_ITEMS = [
    ("1", "Проверка подключения к интернету", "M1"),
    ("2", "Проверка наличия МЭ и АВ", "M2"),
    ("3", "Проверка работоспособности МЭ", "M3"),
    ("4", "Проверка работоспособности АВ", "M4"),
    ("5", "Выполнить все проверки", None),
    ("6", "Вывести и сохранить отчёт", None),
    ("0", "Выход", None),
]


def build_header(os_info: dict, is_root: bool) -> str:
    """Строка заголовка: «SecCheck 0.1 · Astra Linux ... · запуск от root: да»."""
    root_text = "да" if is_root else "нет"
    return "{} {} · {} · запуск от root: {}".format(
        APP_NAME, APP_VERSION, os_info.get("pretty", "неизвестная ОС"), root_text)


def startup_warnings(os_info: dict, is_root: bool) -> List[str]:
    """Предупреждения при запуске: ОС не Astra Linux, запуск без прав root."""
    warnings = []
    if not os_info.get("is_astra", False):
        warnings.append("Внимание: ОС не Astra Linux, результаты могут отличаться.")
    if not is_root:
        warnings.append("Внимание: запуск без прав root. Ограничена проверка M2: правила МЭ "
                        "(nft, iptables) и часть признаков активности не будут прочитаны.")
    return warnings


def format_result_line(result: CheckResult) -> str:
    """Временный однострочный вывод результата (до появления ui/render.py на этапе 2)."""
    return "[{}] {}  {}".format(result.status.value, result.check_id, result.summary)


def print_menu() -> None:
    """Напечатать пункты меню."""
    print()
    for key, text, _check_id in MENU_ITEMS:
        print("  {}  {}".format(key, text))
    print()


def run_menu(controller: Controller, input_func: Callable[[str], str] = input) -> int:
    """Интерактивное меню. Возвращает код завершения программы.

    input_func — функция ввода строки; в тестах подменяется списком ответов.
    Ctrl+C завершает программу с кодом 130, конец ввода (Ctrl+D) — с кодом 0.
    """
    # Словарь «клавиша -> идентификатор проверки» для пунктов 1–4.
    check_by_key = {}
    for key, _text, check_id in MENU_ITEMS:
        if check_id is not None:
            check_by_key[key] = check_id
    try:
        while True:
            print_menu()
            try:
                choice = input_func("Выберите пункт: ").strip()
            except EOFError:
                print()
                return 0

            if choice == "0":
                return 0
            elif choice in check_by_key:
                result = controller.run_check(check_by_key[choice])
                print(format_result_line(result))
            elif choice == "5":
                for check_id in controller.check_ids():
                    print(format_result_line(controller.run_check(check_id)))
            elif choice == "6":
                print("Отчёт будет реализован на этапе 6.")
            else:
                print("Нет такого пункта: «{}». Введите число от 0 до 6.".format(choice))
    except KeyboardInterrupt:
        print()
        print("Прервано пользователем.")
        return EXIT_INTERRUPTED


def build_arg_parser() -> argparse.ArgumentParser:
    """Создать разборщик аргументов командной строки."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Контроль работоспособности антивируса и межсетевого экрана "
                    "на Astra Linux SE.")
    parser.add_argument("--version", action="version",
                        version="{} {}".format(APP_NAME, APP_VERSION))
    parser.add_argument("--config", metavar="PATH", default=None,
                        help="путь к другому файлу config.json")
    return parser


def main(argv: Optional[List[str]] = None, adapter: Optional[SystemAdapter] = None,
         input_func: Callable[[str], str] = input) -> int:
    """Точка входа интерфейса. Возвращает код завершения программы.

    argv, adapter и input_func задаются в тестах; при обычном запуске берутся
    аргументы командной строки, адаптер текущей ОС и стандартный ввод.
    """
    args = build_arg_parser().parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print("Ошибка конфигурации: {}".format(exc), file=sys.stderr)
        return EXIT_ERROR

    if adapter is None:
        try:
            adapter = create_adapter()
        except UnsupportedPlatformError as exc:
            print("Ошибка: {}".format(exc), file=sys.stderr)
            return EXIT_ERROR

    os_info = adapter.os_info()
    is_root = adapter.is_root()
    print(build_header(os_info, is_root))
    for warning in startup_warnings(os_info, is_root):
        print(warning)

    controller = Controller(adapter, config, ResultStore())
    return run_menu(controller, input_func)
