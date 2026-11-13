"""Общие константы и функции SecCheck: статусы проверок, запуск команд, сведения о системе."""

from __future__ import annotations

import os
import subprocess
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


def run_cmd(cmd: List[str], timeout: float) -> Tuple[int, str, str]:
    """Запустить внешнюю команду и вернуть (код возврата, stdout, stderr).

    Команда запускается без оболочки (shell=True не используется), с таймаутом
    и с LC_ALL=C: вывод утилит локализован, а разбираем мы только английский.
    Если программы нет, код равен CMD_NOT_FOUND, если вышло время — CMD_TIMEOUT.
    """
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            errors="replace",  # байты не в UTF-8 заменяются, а не роняют программу
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError:
        return CMD_NOT_FOUND, "", "команда не найдена: " + cmd[0]
    except subprocess.TimeoutExpired:
        # subprocess.run сам завершает процесс, у которого вышло время.
        return CMD_TIMEOUT, "", "команда не завершилась за {} с".format(timeout)
    return completed.returncode, completed.stdout, completed.stderr


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
