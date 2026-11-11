"""Тесты моделей данных и хранилища результатов."""

from __future__ import annotations

import unittest

from core.models import CheckResult, CommandResult, Level, Status
from core.store import ResultStore


def make_result(check_id: str, status: Status = Status.OK) -> CheckResult:
    """Создать простой результат проверки для тестов."""
    return CheckResult(check_id=check_id, title="t", status=status, summary="s")


class ModelsTest(unittest.TestCase):
    """Модели данных."""

    def test_default_lists_are_independent(self) -> None:
        """У каждого результата свой список details и словарь data."""
        first = make_result("M1")
        second = make_result("M2")
        first.details.append("x")
        first.data["k"] = 1
        self.assertEqual(second.details, [])
        self.assertEqual(second.data, {})

    def test_defaults(self) -> None:
        """Время запуска и длительность по умолчанию не заполнены."""
        result = make_result("M1")
        self.assertIsNone(result.started_at)
        self.assertEqual(result.duration_ms, 0)

    def test_level_order(self) -> None:
        """Уровни обнаружения упорядочены по значению."""
        self.assertLess(Level.INSTALLED.value, Level.RUNNING.value)
        self.assertLess(Level.RUNNING.value, Level.ACTIVE.value)

    def test_command_result_flags(self) -> None:
        """Флаги CommandResult по умолчанию ложны."""
        result = CommandResult(returncode=0, stdout="", stderr="")
        self.assertFalse(result.not_found)
        self.assertFalse(result.timed_out)


class ResultStoreTest(unittest.TestCase):
    """Хранилище результатов."""

    def test_put_get(self) -> None:
        """Сохранённый результат можно получить по идентификатору."""
        store = ResultStore()
        result = make_result("M2")
        store.put(result)
        self.assertTrue(store.has("M2"))
        self.assertIs(store.get("M2"), result)

    def test_missing(self) -> None:
        """Невыполненная проверка — None."""
        store = ResultStore()
        self.assertFalse(store.has("M1"))
        self.assertIsNone(store.get("M1"))

    def test_put_replaces(self) -> None:
        """Повторный результат той же проверки заменяет прежний."""
        store = ResultStore()
        store.put(make_result("M1", Status.FAIL))
        store.put(make_result("M1", Status.OK))
        self.assertEqual(store.get("M1").status, Status.OK)
        self.assertEqual(len(store.all()), 1)

    def test_all_sorted_and_clear(self) -> None:
        """all() упорядочен по идентификатору, clear() очищает хранилище."""
        store = ResultStore()
        for check_id in ["M3", "M1", "M2"]:
            store.put(make_result(check_id))
        self.assertEqual([r.check_id for r in store.all()], ["M1", "M2", "M3"])
        store.clear()
        self.assertEqual(store.all(), [])


if __name__ == "__main__":
    unittest.main()
