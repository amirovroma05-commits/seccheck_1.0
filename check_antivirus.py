"""M4. Проверка работоспособности антивируса (АВ).

Программа создаёт тестовый файл EICAR и ждёт реакции резидентной защиты (on-access).
Засчитываются три вида реакции: запрет записи, удаление файла (карантин), запрет чтения.

Строка EICAR хранится только частями и склеивается при выполнении: если записать её
в исходник целиком, антивирус удалит саму программу.
"""

import os
import sys
import tempfile
import time
from typing import List, Tuple

from common import ERROR, FAIL, OK

# Настройки берутся из секции "antivirus_test" файла настроек (см. README.md, «Настройки»):
#   eicar_dir       — каталог, внутри которого создаётся подкаталог для теста,
#                     или null (системный временный каталог);
#   eicar_timeout_s — сколько ждать реакции АВ, с;
#   poll_interval_s — как часто проверять файл, с.

# Имя тестового файла.
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


def show_progress(elapsed: float, timeout_s: float) -> None:
    """Напечатать прогресс ожидания в одну строку (только если вывод — терминал)."""
    if sys.stdout.isatty():
        print("\rОжидание реакции АВ… {:.0f}/{} с".format(elapsed, timeout_s),
              end="", flush=True)


def clear_progress() -> None:
    """Стереть строку прогресса."""
    if sys.stdout.isatty():
        print("\r" + " " * 40 + "\r", end="", flush=True)


def write_and_wait(path: str, content: str, timeout_s: float,
                   interval_s: float) -> Tuple[str, str]:
    """Шаги 3–9. Записать файл и ждать реакции АВ не дольше timeout_s, проверяя файл
    каждые interval_s секунд. Вернуть (статус, итог).
    """
    # Шаг 3. Многие АВ проверяют файл при закрытии после записи, поэтому
    # данные сбрасываются на диск (flush, fsync) до закрытия файла.
    try:
        with open(path, "w", encoding="utf-8") as test_file:
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
        time.sleep(interval_s)
        elapsed = time.monotonic() - start
        show_progress(elapsed, timeout_s)

        # Шаг 6.
        if not os.path.exists(path):
            return OK, "АВ работает: файл удалён или помещён в карантин через {:.0f} с".format(
                elapsed)

        # Шаг 7.
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as test_file:
                test_file.read()
        except PermissionError:
            return OK, "АВ работает: доступ к файлу заблокирован через {:.0f} с".format(
                elapsed)
        except FileNotFoundError:
            # Файл удалили между шагами 6 и 7.
            return OK, "АВ работает: файл удалён или помещён в карантин через {:.0f} с".format(
                elapsed)

        # Шаги 8–9.
        if elapsed >= timeout_s:
            return FAIL, "Резидентная защита не среагировала за {} с".format(timeout_s)


def run(cfg: dict) -> Tuple[str, List[str]]:
    """Выполнить проверку M4. Вернуть (статус, [итог, подробности...]).

    cfg — секция "antivirus_test" файла настроек.
    """
    content = eicar_string()
    # Шаг 2. Создать собственный подкаталог: внутри eicar_dir или, если он null,
    # в системном временном каталоге (dir=None). mkdtemp создаёт каталог с уникальным
    # именем и правами 700, поэтому чужой файл или ссылку на его месте подложить нельзя.
    tmp_dir = tempfile.mkdtemp(prefix="seccheck_", dir=cfg["eicar_dir"])
    path = os.path.join(tmp_dir, FILE_NAME)
    details = ["Тестовый файл: " + path]

    try:
        status, summary = write_and_wait(path, content, cfg["eicar_timeout_s"],
                                         cfg["poll_interval_s"])
    finally:
        # Шаг 10. Удалить свой файл и свой подкаталог в любом случае, в том числе после
        # Ctrl+C. os.rmdir удаляет только пустой каталог, а сам eicar_dir и всё прочее
        # в нём программа не трогает.
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
            os.path.dirname(tmp_dir)))
        details.append("ClamAV: доступ блокируется только при OnAccessPrevention yes")
        details.append("ClamAV: служба clamonacc должна быть запущена")
    return status, [summary] + details
