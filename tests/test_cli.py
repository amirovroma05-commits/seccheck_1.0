"""Тесты консольного интерфейса (меню-заглушка этапа 1)."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from typing import Callable, List

from fake_adapter import FakeAdapter
from ui import cli

NON_ASTRA = {"name": "Ubuntu", "version": "22.04", "is_astra": False,
             "pretty": "Ubuntu 22.04.5 LTS"}


def scripted_input(answers: List[str]) -> Callable[[str], str]:
    """Функция ввода, которая по очереди возвращает ответы, а затем «конец ввода»."""
    remaining = list(answers)

    def fake_input(prompt: str) -> str:
        if not remaining:
            raise EOFError()
        return remaining.pop(0)

    return fake_input


def interrupting_input(prompt: str) -> str:
    """Функция ввода, имитирующая нажатие Ctrl+C."""
    raise KeyboardInterrupt()


class CliTest(unittest.TestCase):
    """Меню и запуск программы."""

    def run_main(self, argv: List[str], adapter: FakeAdapter,
                 input_func: Callable[[str], str]) -> tuple:
        """Запустить cli.main и вернуть (код возврата, stdout, stderr)."""
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv, adapter=adapter, input_func=input_func)
        return code, out.getvalue(), err.getvalue()

    def test_exit_item(self) -> None:
        """Пункт 0 завершает программу с кодом 0, заголовок выводится."""
        code, out, _err = self.run_main([], FakeAdapter(), scripted_input(["0"]))
        self.assertEqual(code, 0)
        self.assertIn("SecCheck 0.1 · Astra Linux 1.7.5 · запуск от root: да", out)
        self.assertNotIn("Внимание", out)

    def test_eof_exits(self) -> None:
        """Конец ввода (Ctrl+D) завершает программу с кодом 0."""
        code, _out, _err = self.run_main([], FakeAdapter(), scripted_input([]))
        self.assertEqual(code, 0)

    def test_ctrl_c_exit_code(self) -> None:
        """Ctrl+C в меню — код 130."""
        code, out, _err = self.run_main([], FakeAdapter(), interrupting_input)
        self.assertEqual(code, cli.EXIT_INTERRUPTED)
        self.assertIn("Прервано", out)

    def test_warnings_without_root_and_astra(self) -> None:
        """Без root и не на Astra выводятся оба предупреждения."""
        adapter = FakeAdapter(os_info=NON_ASTRA, root=False)
        code, out, _err = self.run_main([], adapter, scripted_input(["0"]))
        self.assertEqual(code, 0)
        self.assertIn("ОС не Astra Linux", out)
        self.assertIn("без прав root", out)
        self.assertIn("запуск от root: нет", out)

    def test_menu_items(self) -> None:
        """Неверный пункт, проверка, все проверки и отчёт не роняют меню."""
        answers = ["9", "1", "5", "6", "0"]
        code, out, _err = self.run_main([], FakeAdapter(), scripted_input(answers))
        self.assertEqual(code, 0)
        self.assertIn("Нет такого пункта", out)
        self.assertIn("[NOT_RUN] M1", out)
        self.assertIn("[NOT_RUN] M4", out)
        self.assertIn("этапе 6", out)

    def test_bad_config(self) -> None:
        """Ошибка в config.json — сообщение в stderr и код 3, без трассировки."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "config.json")
            with open(path, "w", encoding="utf-8") as config_file:
                config_file.write("{}")
            code, _out, err = self.run_main(["--config", path], FakeAdapter(),
                                            scripted_input(["0"]))
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("Ошибка конфигурации", err)
        self.assertNotIn("Traceback", err)

    def test_version(self) -> None:
        """--version печатает версию и завершает программу с кодом 0."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as context:
                cli.main(["--version"], adapter=FakeAdapter())
        self.assertEqual(context.exception.code, 0)
        self.assertIn("SecCheck 0.1", out.getvalue())


if __name__ == "__main__":
    unittest.main()
