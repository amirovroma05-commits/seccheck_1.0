"""Тесты контроллера: запуск проверок, перехват сбоев, сохранение результатов."""

from __future__ import annotations

import unittest

from core.config import load_config
from core.controller import CHECK_TITLES, Controller
from core.models import CheckResult, Status
from core.store import ResultStore
from fake_adapter import FakeAdapter


def ok_check(adapter: FakeAdapter, config: dict, store: ResultStore) -> CheckResult:
    """Проверка, которая всегда успешна."""
    return CheckResult(check_id="M1", title="Тест", status=Status.OK, summary="всё хорошо")


def broken_check(adapter: FakeAdapter, config: dict, store: ResultStore) -> CheckResult:
    """Проверка с ошибкой в коде."""
    raise ZeroDivisionError("деление на ноль")


def interrupted_check(adapter: FakeAdapter, config: dict, store: ResultStore) -> CheckResult:
    """Проверка, прерванная пользователем (Ctrl+C)."""
    raise KeyboardInterrupt()


class ControllerTest(unittest.TestCase):
    """Контроллер."""

    def make_controller(self, checks: dict) -> Controller:
        """Контроллер с поддельным адаптером и заданными проверками."""
        self.adapter = FakeAdapter()
        self.store = ResultStore()
        return Controller(self.adapter, load_config(), self.store, checks=checks)

    def test_ok_result_stored_with_timing(self) -> None:
        """Результат сохраняется в store, время запуска и длительность заполняются."""
        controller = self.make_controller({"M1": ok_check})
        result = controller.run_check("M1")
        self.assertEqual(result.status, Status.OK)
        self.assertIs(self.store.get("M1"), result)
        self.assertIsNotNone(result.started_at)
        self.assertGreaterEqual(result.duration_ms, 0)

    def test_refresh_called_before_check(self) -> None:
        """Перед проверкой сбрасывается кэш адаптера."""
        controller = self.make_controller({"M1": ok_check})
        controller.run_check("M1")
        self.assertEqual(self.adapter.refresh_count, 1)

    def test_exception_becomes_error(self) -> None:
        """Исключение модуля превращается в ERROR, программа не падает."""
        controller = self.make_controller({"M2": broken_check})
        result = controller.run_check("M2")
        self.assertEqual(result.status, Status.ERROR)
        self.assertEqual(result.check_id, "M2")
        self.assertEqual(result.title, CHECK_TITLES["M2"])
        self.assertIn("ZeroDivisionError", result.details[0])
        self.assertIs(self.store.get("M2"), result)

    def test_keyboard_interrupt_not_caught(self) -> None:
        """Ctrl+C проходит сквозь контроллер к интерфейсу."""
        controller = self.make_controller({"M4": interrupted_check})
        with self.assertRaises(KeyboardInterrupt):
            controller.run_check("M4")

    def test_not_implemented_check(self) -> None:
        """Проверка без функции получает статус NOT_RUN."""
        controller = self.make_controller({})
        result = controller.run_check("M3")
        self.assertEqual(result.status, Status.NOT_RUN)
        self.assertTrue(self.store.has("M3"))

    def test_unknown_check(self) -> None:
        """Неизвестный идентификатор — ошибка программиста, ValueError."""
        controller = self.make_controller({})
        with self.assertRaises(ValueError):
            controller.run_check("M9")

    def test_options_passed_to_check(self) -> None:
        """Именованные параметры (например, on_progress) доходят до функции проверки."""
        received = {}

        def check_with_progress(adapter: FakeAdapter, config: dict, store: ResultStore,
                                on_progress: object = None) -> CheckResult:
            received["on_progress"] = on_progress
            return CheckResult(check_id="M4", title="", status=Status.OK, summary="")

        controller = self.make_controller({"M4": check_with_progress})
        controller.run_check("M4", on_progress=print)
        self.assertIs(received["on_progress"], print)

    def test_check_ids_order(self) -> None:
        """Проверки идут в порядке M1–M4."""
        controller = self.make_controller({})
        self.assertEqual(controller.check_ids(), ["M1", "M2", "M3", "M4"])


if __name__ == "__main__":
    unittest.main()
