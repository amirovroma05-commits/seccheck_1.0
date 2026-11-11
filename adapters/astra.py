"""Адаптер для Astra Linux Special Edition 1.7 и 1.8.

На этапе 1 реализованы os_info, is_root, hostname, run и path_exists. Остальные методы
появятся на этапах 2 (ping) и 4 (services, processes, packages, netfilter_dump).
"""

from __future__ import annotations

import os
import socket
import subprocess

from adapters.base import SystemAdapter
from core.models import CommandResult


def parse_os_release(text: str) -> dict:
    """Разобрать содержимое /etc/os-release в словарь {ключ: значение}.

    Формат файла: строки КЛЮЧ=значение, значение может быть в кавычках.
    Пустые строки и комментарии (#) пропускаются. Экранирование внутри кавычек
    не разбирается: в полях NAME, ID, VERSION_ID, PRETTY_NAME его не бывает.
    """
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if line == "" or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        # Снять парные кавычки: "Astra Linux" -> Astra Linux
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key.strip()] = value
    return result


class AstraAdapter(SystemAdapter):
    """Реализация SystemAdapter для Astra Linux SE (и для запуска на других Linux)."""

    def __init__(self, os_release_path: str = "/etc/os-release",
                 astra_version_path: str = "/etc/astra_version") -> None:
        """Создать адаптер. Пути к системным файлам можно подменить в тестах."""
        self.os_release_path = os_release_path
        self.astra_version_path = astra_version_path

    def _read_text(self, path: str) -> str:
        """Прочитать текстовый файл; при любой ошибке чтения вернуть пустую строку."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as text_file:
                return text_file.read()
        except OSError:
            return ""

    def os_info(self) -> dict:
        """Сведения об ОС из /etc/os-release и /etc/astra_version.

        is_astra истинно, если ID=astra или есть файл /etc/astra_version.
        Если /etc/astra_version есть, версия берётся из него (первая строка).
        """
        fields = parse_os_release(self._read_text(self.os_release_path))
        name = fields.get("NAME", "Linux")
        version = fields.get("VERSION_ID", "")
        pretty = fields.get("PRETTY_NAME", name)

        is_astra = fields.get("ID", "") == "astra"
        if os.path.exists(self.astra_version_path):
            is_astra = True
            # TODO(стенд): прислать вывод `cat /etc/astra_version` на 1.7 и 1.8, чтобы
            # уточнить формат версии (например, «1.7.5» или «SE 1.7.5»).
            lines = self._read_text(self.astra_version_path).strip().splitlines()
            if lines and lines[0].strip() != "":
                version = lines[0].strip()

        return {"name": name, "version": version, "is_astra": is_astra, "pretty": pretty}

    def is_root(self) -> bool:
        """Запущена ли программа с правами root (эффективный UID равен 0)."""
        return os.geteuid() == 0

    def hostname(self) -> str:
        """Имя компьютера."""
        return socket.gethostname()

    def run(self, cmd: list, timeout: float) -> CommandResult:
        """Запустить команду cmd (list[str]) без оболочки, с таймаутом и LC_ALL=C.

        LC_ALL=C нужен, чтобы вывод systemctl, ufw, dpkg был на английском: разбираем
        только его. Исключения не выбрасываются, всё отражается в CommandResult.
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
            return CommandResult(returncode=-1, stdout="",
                                 stderr="команда не найдена: " + str(cmd[0]),
                                 not_found=True)
        except subprocess.TimeoutExpired:
            # subprocess.run сам завершает процесс, у которого вышло время.
            return CommandResult(returncode=-2, stdout="",
                                 stderr="команда не завершилась за {} с".format(timeout),
                                 timed_out=True)
        except PermissionError:
            # Нет права на запуск файла (например, его не пропускает ЗПС).
            return CommandResult(returncode=-3, stdout="",
                                 stderr="нет права на запуск: " + str(cmd[0]))
        return CommandResult(returncode=completed.returncode,
                             stdout=completed.stdout, stderr=completed.stderr)

    def ping(self, host: str, timeout_s: int) -> bool:
        """Будет реализован на этапе 2 (модуль M1)."""
        raise NotImplementedError("AstraAdapter.ping появится на этапе 2")

    def services(self) -> dict:
        """Будет реализован на этапе 4 (модуль M2)."""
        raise NotImplementedError("AstraAdapter.services появится на этапе 4")

    def processes(self) -> set:
        """Будет реализован на этапе 4 (модуль M2)."""
        raise NotImplementedError("AstraAdapter.processes появится на этапе 4")

    def packages(self) -> set:
        """Будет реализован на этапе 4 (модуль M2)."""
        raise NotImplementedError("AstraAdapter.packages появится на этапе 4")

    def path_exists(self, path: str) -> bool:
        """Существует ли файл или каталог path."""
        return os.path.exists(path)

    def netfilter_dump(self) -> dict:
        """Будет реализован на этапе 4 (модуль M2)."""
        raise NotImplementedError("AstraAdapter.netfilter_dump появится на этапе 4")
