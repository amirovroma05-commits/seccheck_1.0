"""Поддельный адаптер ОС для тестов: все ответы задаются заранее в конструкторе."""

from __future__ import annotations

from typing import Optional

from adapters.base import SystemAdapter
from core.models import CommandResult


class FakeAdapter(SystemAdapter):
    """Реализация SystemAdapter без обращения к системе.

    run() берёт ответ из словаря commands по ключу tuple(cmd); для незнакомой
    команды возвращает «команда не найдена». Все вызовы run() запоминаются
    в run_calls, вызовы refresh() считаются в refresh_count.
    """

    def __init__(self, os_info: Optional[dict] = None, root: bool = True,
                 hostname: str = "test-host", commands: Optional[dict] = None,
                 ping_results: Optional[dict] = None, services: Optional[dict] = None,
                 processes: Optional[set] = None, packages: Optional[set] = None,
                 existing_paths: Optional[set] = None,
                 netfilter: Optional[dict] = None) -> None:
        """Создать адаптер с заранее заданными ответами (по умолчанию — «пустая» система)."""
        if os_info is None:
            os_info = {"name": "Astra Linux", "version": "1.7.5", "is_astra": True,
                       "pretty": "Astra Linux 1.7.5"}
        self._os_info = os_info
        self._root = root
        self._hostname = hostname
        self._commands = commands if commands is not None else {}
        self._ping_results = ping_results if ping_results is not None else {}
        self._services = services if services is not None else {}
        self._processes = processes if processes is not None else set()
        self._packages = packages if packages is not None else set()
        self._existing_paths = existing_paths if existing_paths is not None else set()
        self._netfilter = netfilter if netfilter is not None else {}
        self.run_calls = []      # list[list[str]]: какие команды запускались
        self.refresh_count = 0

    def os_info(self) -> dict:
        """Заданные сведения об ОС."""
        return self._os_info

    def is_root(self) -> bool:
        """Заданный признак root."""
        return self._root

    def hostname(self) -> str:
        """Заданное имя компьютера."""
        return self._hostname

    def run(self, cmd: list, timeout: float) -> CommandResult:
        """Ответ из словаря commands; незнакомая команда — «не найдена»."""
        self.run_calls.append(list(cmd))
        key = tuple(cmd)
        if key in self._commands:
            return self._commands[key]
        return CommandResult(returncode=-1, stdout="", stderr="", not_found=True)

    def ping(self, host: str, timeout_s: int) -> bool:
        """Заданный результат ping; по умолчанию узел не отвечает."""
        return self._ping_results.get(host, False)

    def services(self) -> dict:
        """Заданные службы."""
        return self._services

    def processes(self) -> set:
        """Заданные процессы."""
        return self._processes

    def packages(self) -> set:
        """Заданные пакеты."""
        return self._packages

    def path_exists(self, path: str) -> bool:
        """Существует ли путь в заданном наборе."""
        return path in self._existing_paths

    def netfilter_dump(self) -> dict:
        """Заданные выводы nft и iptables."""
        return self._netfilter

    def refresh(self) -> None:
        """Посчитать вызов сброса кэша."""
        self.refresh_count += 1
