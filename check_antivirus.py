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
import tempfile
import time
from typing import List, Tuple

from common import ERROR, FAIL, OK

# Настройки берутся из секции "antivirus_test" файла настроек (см. README.md, «Настройки»):
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
    # Шаг 3. Одна строка перед ожиданием, без счётчика.
    print("Ожидание реакции АВ (до {} с)…".format(timeout_s))
    start = time.monotonic()
    # Резидентная защита проверяет файл при закрытии после записи; `with` закрывает файл
    # до начала ожидания.
    try:
        with open(path, "w", encoding="utf-8") as test_file:
            test_file.write(content)
    except PermissionError:
        # Шаг 4. PermissionError — это EACCES или EPERM: запись запретил АВ.
        return OK, detected(time.monotonic() - start, "запись заблокирована")
    except OSError as exc:
        # Другие ошибки (нет места на диске и т. п.) реакцией АВ не считаются.
        return ERROR, "ошибка проверки (запись тестового файла: {})".format(os_error_text(exc))

    while True:
        # Шаг 5.
        time.sleep(interval_s)
        elapsed = time.monotonic() - start

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

    Вернуть (подробности, предупреждения). os.rmdir удаляет только пустой каталог.
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
    # Шаг 2. Создать собственный подкаталог во временном каталоге системы. mkdtemp
    # создаёт каталог с уникальным именем и правами 700, поэтому чужой файл или ссылку
    # на его месте подложить нельзя.
    try:
        tmp_dir = tempfile.mkdtemp(prefix="seccheck_")
    except OSError as exc:
        return ERROR, ["ошибка проверки (создание каталога: {})".format(
            os_error_text(exc))], []
    path = os.path.join(tmp_dir, FILE_NAME)
    details = ["Тестовый файл: " + path]

    finished = False  # проверка дошла до конца без исключения
    try:
        status, result = write_and_wait(path, content, cfg["eicar_timeout_s"],
                                        cfg["poll_interval_s"])
        finished = True
    finally:
        # Шаг 10. Удалить файл и подкаталог при любом исходе, в том числе после Ctrl+C.
        cleanup_details, warnings = remove_test_files(path, tmp_dir)
        if not finished:
            # Проверку прервали: результата не будет, поэтому предупреждения печатаются
            # сразу, затем исключение идёт дальше.
            for line in warnings:
                print(line)
    details.extend(cleanup_details)

    # Предупреждения о неудалённом файле печатаются всегда, а не только с -v.
    brief = [result]
    if status == FAIL:
        # Шаг 11. Подсказка; каталог, который должна охватывать защита, — только с -v.
        brief.append("Проверьте, что включена постоянная защита (проверка файлов при доступе)")
        details.append("Каталог {} должен входить в область постоянной защиты".format(
            os.path.dirname(tmp_dir)))
    return status, brief + warnings, details
