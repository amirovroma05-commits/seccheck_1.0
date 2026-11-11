"""Проверка исходников на совместимость с Python 3.7 (Astra SE 1.7).

Среда разработки может быть новее 3.7, поэтому синтаксис проверяется через
ast.parse(..., feature_version=(3, 7)): так ловятся `:=`, `match` и позиционные `/`
параметры. Дополнительно ищутся функции и модули, которых нет в 3.7.
Проверка не исчерпывающая, окончательная — запуск тестов на стенде.
"""

from __future__ import annotations

import ast
import os
import sys
import unittest
from typing import List

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Модули стандартной библиотеки, появившиеся после Python 3.7.
FORBIDDEN_MODULES = {"zoneinfo", "tomllib", "graphlib"}
# Методы и функции, появившиеся после Python 3.7.
FORBIDDEN_ATTRIBUTES = {"removeprefix", "removesuffix"}


def project_python_files() -> List[str]:
    """Все .py файлы проекта, кроме служебных каталогов."""
    paths = []
    for root, dirs, files in os.walk(PROJECT_DIR):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git", ".vscode")]
        for name in files:
            if name.endswith(".py"):
                paths.append(os.path.join(root, name))
    return sorted(paths)


def read_source(path: str) -> str:
    """Прочитать исходный текст файла."""
    with open(path, "r", encoding="utf-8") as source_file:
        return source_file.read()


class Py37CompatTest(unittest.TestCase):
    """Совместимость с Python 3.7."""

    def test_files_found(self) -> None:
        """Тест действительно видит файлы проекта."""
        self.assertIn(os.path.join(PROJECT_DIR, "main.py"), project_python_files())

    @unittest.skipIf(sys.version_info < (3, 8), "feature_version есть только в Python 3.8+")
    def test_syntax_37(self) -> None:
        """Каждый файл разбирается грамматикой Python 3.7."""
        for path in project_python_files():
            with self.subTest(path=path):
                ast.parse(read_source(path), filename=path, feature_version=(3, 7))

    def test_future_annotations(self) -> None:
        """В каждом файле есть `from __future__ import annotations`."""
        for path in project_python_files():
            with self.subTest(path=path):
                self.assertIn("from __future__ import annotations", read_source(path))

    def test_no_new_stdlib(self) -> None:
        """Не используются модули и методы, которых нет в Python 3.7."""
        for path in project_python_files():
            tree = ast.parse(read_source(path), filename=path)
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".")[0]]
                    if node.module == "functools":
                        for alias in node.names:
                            self.assertNotEqual(alias.name, "cache", path)
                for name in names:
                    self.assertNotIn(name, FORBIDDEN_MODULES, path)
                if isinstance(node, ast.Attribute):
                    where = "{}:{}".format(path, node.lineno)
                    self.assertNotIn(node.attr, FORBIDDEN_ATTRIBUTES, where)
                    # functools.cache (Python 3.9+); другие атрибуты cache не трогаем.
                    if isinstance(node.value, ast.Name) and node.value.id == "functools":
                        self.assertNotEqual(node.attr, "cache", where)


if __name__ == "__main__":
    unittest.main()
