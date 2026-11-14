"""M4. Проверка работоспособности антивируса (АВ).

Отвечает на вопрос: реагирует ли резидентная защита АВ на тестовый файл.

Программа создаёт тестовый файл EICAR и ждёт реакции резидентной защиты (on-access).
Засчитываются три вида реакции: запрет записи, удаление файла (карантин), запрет чтения.
Реакцией считается только PermissionError (EACCES или EPERM); другие ошибки ввода-вывода
(нет каталога, нет места на диске) дают статус ERROR.

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


def os_error_text(exc: OSError) -> str:
    """Краткое описание ошибки ввода-вывода для итоговой строки."""
    return exc.strerror or str(exc)


def detected(elapsed: float, how: str) -> str:
    """Итог при реакции АВ: «тестовый файл обнаружен за N с (как)»."""
    return "тестовый файл обнаружен за {:.0f} с ({})".format(elapsed, how)


def write_and_wait(path: str, content: str, timeout_s: float,
                   interval_s: float) -> Tuple[str, str]:
    """Шаги 3–9. Записать файл и ждать реакции АВ не дольше timeout_s, проверяя файл
    каждые interval_s секунд. Вернуть (статус, результат).
    """
    start = time.monotonic()
    # Шаг 3. Многие АВ проверяют файл при закрытии после записи, поэтому
    # данные сбрасываются на диск (flush, fsync) до закрытия файла.
    try:
        with open(path, "w", encoding="utf-8") as test_file:
            test_file.write(content)
            test_file.flush()
            os.fsync(test_file.fileno())
    except PermissionError:
        # Шаг 4. PermissionError — это EACCES или EPERM: запись запретил АВ.
        return OK, detected(time.monotonic() - start, "запись заблокирована")
    except OSError as exc:
        # Другие ошибки (нет каталога, нет места) реакцией АВ не считаются.
        return ERROR, "ошибка проверки (запись тестового файла: {})".format(os_error_text(exc))

    while True:
        # Шаг 5.
        time.sleep(interval_s)
        elapsed = time.monotonic() - start
        show_progress(elapsed, timeout_s)

        # Шаг 6.
        if not os.path.exists(path):
            return OK, detected(elapsed, "файл удалён")

        # Шаг 7.
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as test_file:
                test_file.read()
        except PermissionError:
            return OK, detected(elapsed, "доступ к файлу заблокирован")
        except FileNotFoundError:
            # Файл удалили между шагами 6 и 7.
            return OK, detected(elapsed, "файл удалён")
        except OSError as exc:
            return ERROR, "ошибка проверки (чтение тестового файла: {})".format(
                os_error_text(exc))

        # Шаги 8–9.
        if elapsed >= timeout_s:
            return FAIL, "тестовый файл не обнаружен за {} с".format(timeout_s)


def remove_test_files(path: str, tmp_dir: str) -> Tuple[List[str], List[str]]:
    """Шаг 10. Удалить свой тестовый файл и свой подкаталог.

    Вернуть (подробности, предупреждения). os.rmdir удаляет только пустой каталог, а сам
    eicar_dir и всё прочее в нём программа не трогает.
    """
    details = []
    warnings = []
    try:
        os.remove(path)
        details.append("Тестовый файл удалён программой")
    except FileNotFoundError:
        details.append("Тестовый файл к моменту удаления уже отсутствовал")
    except OSError as exc:
        warnings.append("Внимание: не удалось удалить {}: {}".format(
            path, os_error_text(exc)))
    try:
        os.rmdir(tmp_dir)
    except OSError as exc:
        warnings.append("Внимание: не удалось удалить каталог {}: {}".format(
            tmp_dir, os_error_text(exc)))
    return details, warnings


def run(cfg: dict) -> Tuple[str, List[str], List[str]]:
    """Выполнить проверку M4. Вернуть (статус, краткие строки, подробности).

    cfg — секция "antivirus_test" файла настроек.
    """
    content = eicar_string()
    # Шаг 2. Создать собственный подкаталог: внутри eicar_dir или, если он null,
    # в системном временном каталоге (dir=None). mkdtemp создаёт каталог с уникальным
    # именем и правами 700, поэтому чужой файл или ссылку на его месте подложить нельзя.
    try:
        tmp_dir = tempfile.mkdtemp(prefix="seccheck_", dir=cfg["eicar_dir"])
    except OSError as exc:
        return ERROR, ["ошибка проверки (создание каталога: {})".format(
            os_error_text(exc))], []
    path = os.path.join(tmp_dir, FILE_NAME)
    details = ["Тестовый файл: " + path]

    try:
        status, result = write_and_wait(path, content, cfg["eicar_timeout_s"],
                                        cfg["poll_interval_s"])
    except BaseException:
        # Ctrl+C (KeyboardInterrupt) или неожиданный сбой: результата проверки не будет,
        # поэтому файл удаляется здесь, а предупреждения о неудаче печатаются сразу.
        # Затем исключение передаётся дальше (raise).
        clear_progress()
        _cleanup_details, warnings = remove_test_files(path, tmp_dir)
        for line in warnings:
            print(line)
        raise

    # Шаг 10. Обычное завершение: удалить файл. Предупреждения о неудалённом файле или
    # каталоге печатаются всегда, а не только с -v: на диске остался тестовый файл.
    clear_progress()
    cleanup_details, warnings = remove_test_files(path, tmp_dir)
    details.extend(cleanup_details)

    brief = [result]
    if status == FAIL:
        # Шаг 11. Подсказка; каталог, который должна охватывать защита, — только с -v.
        brief.append("Проверьте, что включена постоянная защита (проверка файлов при доступе)")
        details.append("Каталог {} должен входить в область постоянной защиты".format(
            os.path.dirname(tmp_dir)))
    return status, brief + warnings, details
