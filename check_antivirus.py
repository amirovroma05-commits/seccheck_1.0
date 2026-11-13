"""M4. Проверка работоспособности антивируса (АВ).

Программа создаёт тестовый файл EICAR и ждёт реакции резидентной защиты (on-access).
Засчитываются три вида реакции: запрет записи, удаление файла (карантин), запрет чтения.

Строка EICAR хранится только частями и склеивается при выполнении: если записать её
в исходник целиком, антивирус удалит саму программу.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from typing import List, Tuple

from common import ERROR, FAIL, OK

# Настройки проверки.
EICAR_TIMEOUT = 30      # сколько ждать реакции АВ, с
POLL_INTERVAL = 1       # как часто проверять файл, с
FILE_NAME = "eicar_test.txt"

# Части тестовой строки EICAR (стандартный безопасный тестовый файл для АВ).
EICAR_PARTS = [
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$",
    "EICAR-STANDARD-",
    "ANTIVIRUS-TEST-",
    "FILE!$H+H*",
]


def eicar_string() -> str:
    """Шаг 1. Собрать строку EICAR из частей."""
    return "".join(EICAR_PARTS)


def show_progress(elapsed: float) -> None:
    """Напечатать прогресс ожидания в одну строку (только если вывод — терминал)."""
    if sys.stdout.isatty():
        print("\rОжидание реакции АВ… {:.0f}/{} с".format(elapsed, EICAR_TIMEOUT),
              end="", flush=True)


def clear_progress() -> None:
    """Стереть строку прогресса."""
    if sys.stdout.isatty():
        print("\r" + " " * 40 + "\r", end="", flush=True)


def write_and_wait(path: str, content: str) -> Tuple[str, str]:
    """Шаги 3–8. Записать файл и ждать реакции АВ. Вернуть (статус, итог)."""
    # Шаг 3. Многие АВ проверяют файл при закрытии после записи, поэтому
    # данные сбрасываются на диск (flush, fsync) до закрытия файла.
    try:
        with open(path, "w", encoding="ascii") as test_file:
            test_file.write(content)
            test_file.flush()
            os.fsync(test_file.fileno())
    except PermissionError:
        # Шаг 4.
        return OK, "АВ работает: запись тестового файла заблокирована"
    except OSError as exc:
        # Другие ошибки (нет места, сбой диска) реакцией АВ не считаются.
        return ERROR, "Не удалось записать тестовый файл: {}".format(exc)

    start = time.monotonic()
    while True:
        # Шаг 5.
        time.sleep(POLL_INTERVAL)
        elapsed = time.monotonic() - start
        show_progress(elapsed)

        # Шаг 6.
        if not os.path.exists(path):
            return OK, "АВ работает: файл удалён или помещён в карантин через {:.0f} с".format(
                elapsed)

        # Шаг 7.
        try:
            with open(path, "r", encoding="ascii", errors="replace") as test_file:
                test_file.read()
        except PermissionError:
            return OK, "АВ работает: доступ к файлу заблокирован через {:.0f} с".format(
                elapsed)
        except FileNotFoundError:
            # Файл удалили между шагами 6 и 7.
            return OK, "АВ работает: файл удалён или помещён в карантин через {:.0f} с".format(
                elapsed)

        # Шаги 8–9.
        if elapsed >= EICAR_TIMEOUT:
            return FAIL, "Резидентная защита не среагировала за {} с".format(EICAR_TIMEOUT)


def run() -> Tuple[str, List[str]]:
    """Выполнить проверку M4. Вернуть (статус, [итог, подробности...])."""
    content = eicar_string()
    # Шаг 2. Временный каталог.
    tmp_dir = tempfile.mkdtemp(prefix="seccheck_")
    path = os.path.join(tmp_dir, FILE_NAME)
    details = ["Тестовый файл: " + path]

    try:
        status, summary = write_and_wait(path, content)
    finally:
        # Шаг 10. Удалить файл и каталог в любом случае, в том числе после Ctrl+C.
        clear_progress()
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            details.append("Внимание: не удалось удалить {}: {}".format(path, exc))
        try:
            os.rmdir(tmp_dir)
        except OSError as exc:
            details.append("Внимание: не удалось удалить каталог {}: {}".format(tmp_dir, exc))

    if status == FAIL:
        # Подсказки по частым причинам отказа для ClamAV (clamd.conf).
        details.append("ClamAV: каталог {} должен входить в OnAccessIncludePath".format(
            tempfile.gettempdir()))
        details.append("ClamAV: доступ блокируется только при OnAccessPrevention yes")
        details.append("ClamAV: служба clamonacc должна быть запущена")
    return status, [summary] + details
