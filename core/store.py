"""Хранилище результатов проверок за один запуск программы."""

from __future__ import annotations

from typing import List, Optional

from core.models import CheckResult


class ResultStore:
    """Хранит последний результат каждой проверки по её идентификатору ("M1".."M4").

    Повторный запуск проверки заменяет её прежний результат. Хранилищем пользуются
    модули (M3 и M4 читают результат M2) и отчёт M5.
    """

    def __init__(self) -> None:
        """Создать пустое хранилище."""
        self._results = {}  # dict[str, CheckResult]: идентификатор -> результат

    def put(self, result: CheckResult) -> None:
        """Сохранить результат, заменив прежний результат той же проверки."""
        self._results[result.check_id] = result

    def get(self, check_id: str) -> Optional[CheckResult]:
        """Вернуть результат проверки или None, если она не выполнялась."""
        return self._results.get(check_id)

    def has(self, check_id: str) -> bool:
        """Проверить, есть ли результат проверки с таким идентификатором."""
        return check_id in self._results

    def all(self) -> List[CheckResult]:
        """Вернуть все результаты, упорядоченные по идентификатору (M1, M2, ...)."""
        return [self._results[key] for key in sorted(self._results)]

    def clear(self) -> None:
        """Удалить все результаты."""
        self._results.clear()
