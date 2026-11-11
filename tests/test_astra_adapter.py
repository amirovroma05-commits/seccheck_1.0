"""Тесты AstraAdapter: разбор os-release и запуск внешних команд.

Команды запускаются настоящие, но безопасные: текущий интерпретатор Python
(sys.executable) с коротким скриптом. Ни root, ни сеть не нужны.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

from adapters.astra import AstraAdapter, parse_os_release

ASTRA_OS_RELEASE = (
    'PRETTY_NAME="Astra Linux"\n'
    'NAME="Astra Linux"\n'
    'ID=astra\n'
    'ID_LIKE=debian\n'
    'VERSION_ID=1.7_x86-64\n'
)  # TODO(стенд): заменить реальным выводом `cat /etc/os-release` с Astra SE 1.7 и 1.8

UBUNTU_OS_RELEASE = (
    '# комментарий\n'
    'PRETTY_NAME="Ubuntu 22.04.5 LTS"\n'
    'NAME="Ubuntu"\n'
    'VERSION_ID="22.04"\n'
    'ID=ubuntu\n'
)


class ParseOsReleaseTest(unittest.TestCase):
    """Разбор /etc/os-release."""

    def test_quotes_removed(self) -> None:
        """Кавычки вокруг значений снимаются, комментарии пропускаются."""
        fields = parse_os_release(UBUNTU_OS_RELEASE)
        self.assertEqual(fields["PRETTY_NAME"], "Ubuntu 22.04.5 LTS")
        self.assertEqual(fields["VERSION_ID"], "22.04")
        self.assertEqual(fields["ID"], "ubuntu")
        self.assertNotIn("# комментарий", fields)

    def test_value_with_equals(self) -> None:
        """Знак = внутри значения не разрывает его."""
        self.assertEqual(parse_os_release("A='x=y'\n")["A"], "x=y")


class OsInfoTest(unittest.TestCase):
    """Метод os_info на подменённых файлах."""

    def setUp(self) -> None:
        """Создать временный каталог для поддельных системных файлов."""
        self.tmp_dir = tempfile.mkdtemp(prefix="seccheck_test_")
        self.os_release = os.path.join(self.tmp_dir, "os-release")
        self.astra_version = os.path.join(self.tmp_dir, "astra_version")

    def tearDown(self) -> None:
        """Удалить временный каталог."""
        shutil.rmtree(self.tmp_dir)

    def write(self, path: str, text: str) -> None:
        """Записать текст в файл."""
        with open(path, "w", encoding="utf-8") as text_file:
            text_file.write(text)

    def adapter(self) -> AstraAdapter:
        """Адаптер, читающий файлы из временного каталога."""
        return AstraAdapter(os_release_path=self.os_release,
                            astra_version_path=self.astra_version)

    def test_astra_by_id(self) -> None:
        """ID=astra означает Astra Linux."""
        self.write(self.os_release, ASTRA_OS_RELEASE)
        info = self.adapter().os_info()
        self.assertTrue(info["is_astra"])
        self.assertEqual(info["name"], "Astra Linux")
        self.assertEqual(info["version"], "1.7_x86-64")

    def test_astra_version_file_overrides(self) -> None:
        """Версия из /etc/astra_version важнее VERSION_ID, и файл сам признак Astra."""
        self.write(self.os_release, UBUNTU_OS_RELEASE)
        self.write(self.astra_version, "1.7.5\n")
        info = self.adapter().os_info()
        self.assertTrue(info["is_astra"])
        self.assertEqual(info["version"], "1.7.5")

    def test_not_astra(self) -> None:
        """Другой дистрибутив распознаётся как не Astra."""
        self.write(self.os_release, UBUNTU_OS_RELEASE)
        info = self.adapter().os_info()
        self.assertFalse(info["is_astra"])
        self.assertEqual(info["pretty"], "Ubuntu 22.04.5 LTS")

    def test_missing_os_release(self) -> None:
        """Без /etc/os-release программа не падает."""
        info = self.adapter().os_info()
        self.assertFalse(info["is_astra"])
        self.assertEqual(info["name"], "Linux")
        self.assertEqual(set(info), {"name", "version", "is_astra", "pretty"})


class RunTest(unittest.TestCase):
    """Метод run: таймаут, LC_ALL=C, отсутствующая команда."""

    def setUp(self) -> None:
        """Создать адаптер."""
        self.adapter = AstraAdapter()

    def test_success(self) -> None:
        """Вывод и код возврата передаются как есть."""
        result = self.adapter.run([sys.executable, "-c", "print('hello')"], timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "hello")
        self.assertFalse(result.not_found)
        self.assertFalse(result.timed_out)

    def test_nonzero_exit_and_stderr(self) -> None:
        """Ненулевой код возврата и stderr сохраняются."""
        code = "import sys; sys.stderr.write('bad'); sys.exit(3)"
        result = self.adapter.run([sys.executable, "-c", code], timeout=10)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stderr, "bad")

    def test_lc_all_is_c(self) -> None:
        """Команде передаётся LC_ALL=C."""
        code = "import os; print(os.environ.get('LC_ALL'))"
        result = self.adapter.run([sys.executable, "-c", code], timeout=10)
        self.assertEqual(result.stdout.strip(), "C")

    def test_not_found(self) -> None:
        """Отсутствующая утилита — not_found и код -1, без исключения."""
        result = self.adapter.run(["seccheck-no-such-command"], timeout=5)
        self.assertTrue(result.not_found)
        self.assertEqual(result.returncode, -1)

    def test_timeout(self) -> None:
        """Зависшая команда прерывается по таймауту — timed_out и код -2."""
        code = "import time; time.sleep(10)"
        result = self.adapter.run([sys.executable, "-c", code], timeout=0.5)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, -2)

    def test_not_executable(self) -> None:
        """Файл без права на выполнение — код -3, без исключения."""
        tmp_dir = tempfile.mkdtemp(prefix="seccheck_test_")
        try:
            path = os.path.join(tmp_dir, "script.sh")
            with open(path, "w") as script:
                script.write("#!/bin/sh\necho hi\n")
            os.chmod(path, 0o644)
            result = self.adapter.run([path], timeout=5)
            # Без бита x файл не запускается даже от root.
            self.assertEqual(result.returncode, -3)
        finally:
            shutil.rmtree(tmp_dir)

    def test_is_root_matches_euid(self) -> None:
        """is_root совпадает с эффективным UID процесса."""
        self.assertEqual(self.adapter.is_root(), os.geteuid() == 0)


if __name__ == "__main__":
    unittest.main()
