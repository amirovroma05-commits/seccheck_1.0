"""Абстрактный адаптер ОС: перечень методов, которые нужны модулям проверок.

Модули работают только с этим интерфейсом. Для новой ОС (например, Windows) достаточно
написать ещё одну реализацию с теми же методами, модули проверок при этом не меняются.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import CommandResult


class SystemAdapter(ABC):
    """Интерфейс доступа к операционной системе."""

    @abstractmethod
    def os_info(self) -> dict:
        """Сведения об ОС: {"name", "version", "is_astra", "pretty"}."""

    @abstractmethod
    def is_root(self) -> bool:
        """Запущена ли программа с правами root."""

    @abstractmethod
    def hostname(self) -> str:
        """Имя компьютера."""

    @abstractmethod
    def run(self, cmd: list, timeout: float) -> CommandResult:
        """Запустить внешнюю команду cmd (list[str]) с таймаутом timeout секунд."""

    @abstractmethod
    def ping(self, host: str, timeout_s: int) -> bool:
        """Отправить один ICMP-запрос узлу host; True, если пришёл ответ."""

    @abstractmethod
    def services(self) -> dict:
        """Службы и их состояние: {"clamav-daemon": "active", ...}."""

    @abstractmethod
    def processes(self) -> set:
        """Имена запущенных процессов: {"clamd", "clamonacc", ...}."""

    @abstractmethod
    def packages(self) -> set:
        """Имена установленных пакетов."""

    @abstractmethod
    def path_exists(self, path: str) -> bool:
        """Существует ли файл или каталог path."""

    @abstractmethod
    def netfilter_dump(self) -> dict:
        """Сырые выводы nft и iptables: {"nft": CommandResult, ...} (см. SPEC.md, разд. 5)."""

    def refresh(self) -> None:
        """Сбросить кэш сведений о системе. Контроллер вызывает его перед каждой проверкой.

        В базовом классе кэша нет, поэтому метод ничего не делает.
        """
