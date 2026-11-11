"""Контроллер: запускает проверки и сохраняет их результаты в ResultStore.

Интерфейс (консольный, а позже и оконный) обращается к проверкам только через
контроллер и ничего не знает об ОС.
"""

from __future__ import annotations

import time
import traceback
from datetime import datetime
from typing import Callable, Dict, List, Optional

from adapters.base import SystemAdapter
from core.models import CheckResult, Status
from core.store import ResultStore

# Все проверки программы в порядке выполнения и их названия.
CHECK_TITLES = {
    "M1": "Подключение к интернету",
    "M2": "Наличие МЭ и АВ",
    "M3": "Работоспособность МЭ",
    "M4": "Работоспособность АВ",
}

# Функция проверки: run_mX(adapter, config, store, ...) -> CheckResult.
CheckFunction = Callable[..., CheckResult]


def default_checks() -> Dict[str, CheckFunction]:
    """Вернуть уже реализованные проверки: {идентификатор: функция}.

    На этапе 1 модулей проверок ещё нет. Они будут добавляться сюда по мере
    реализации (M1 — этап 2, M4 — этап 3, M2 — этап 4, M3 — этап 5).
    """
    return {}


class Controller:
    """Запускает проверки, перехватывает их сбои и хранит результаты."""

    def __init__(self, adapter: SystemAdapter, config: dict, store: ResultStore,
                 checks: Optional[Dict[str, CheckFunction]] = None) -> None:
        """Создать контроллер.

        checks — словарь {идентификатор: функция проверки}; если не задан, берутся
        default_checks(). Параметр нужен тестам, чтобы подставить свои функции.
        """
        self.adapter = adapter
        self.config = config
        self.store = store
        if checks is None:
            checks = default_checks()
        self.checks = checks

    def check_ids(self) -> List[str]:
        """Идентификаторы всех проверок в порядке выполнения: ["M1", ..., "M4"]."""
        return list(CHECK_TITLES)

    def run_check(self, check_id: str, **options: object) -> CheckResult:
        """Выполнить одну проверку и сохранить её результат в store.

        options передаются в функцию проверки как именованные аргументы
        (например, on_progress для M4). Любое исключение модуля превращается
        в результат со статусом ERROR. KeyboardInterrupt (Ctrl+C) не перехватывается:
        его обрабатывает интерфейс.
        """
        if check_id not in CHECK_TITLES:
            raise ValueError("неизвестная проверка: " + check_id)

        started_at = datetime.now()
        start = time.monotonic()

        check_function = self.checks.get(check_id)
        if check_function is None:
            result = CheckResult(check_id=check_id, title=CHECK_TITLES[check_id],
                                 status=Status.NOT_RUN,
                                 summary="Проверка пока не реализована")
        else:
            try:
                # Сбросить кэш адаптера, чтобы проверка видела свежее состояние системы.
                self.adapter.refresh()
                result = check_function(self.adapter, self.config, self.store, **options)
            except Exception as exc:
                details = ["Исключение {}: {}".format(type(exc).__name__, exc)]
                details.extend(traceback.format_exc().rstrip().splitlines())
                result = CheckResult(check_id=check_id, title=CHECK_TITLES[check_id],
                                     status=Status.ERROR,
                                     summary="Сбой программы при выполнении проверки",
                                     details=details)

        result.started_at = started_at
        result.duration_ms = int((time.monotonic() - start) * 1000)
        self.store.put(result)
        return result
