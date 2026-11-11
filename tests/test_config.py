"""Тесты загрузки и проверки config.json."""

from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
import unittest

from core.config import DEFAULT_CONFIG_PATH, ConfigError, load_config, validate_config


class ConfigTest(unittest.TestCase):
    """Загрузка и проверка настроек."""

    def setUp(self) -> None:
        """Взять настройки по умолчанию и создать временный каталог."""
        self.config = load_config()
        self.tmp_dir = tempfile.mkdtemp(prefix="seccheck_test_")

    def tearDown(self) -> None:
        """Удалить временный каталог."""
        shutil.rmtree(self.tmp_dir)

    def write_file(self, text: str) -> str:
        """Записать текст во временный файл и вернуть путь к нему."""
        path = os.path.join(self.tmp_dir, "config.json")
        with open(path, "w", encoding="utf-8") as config_file:
            config_file.write(text)
        return path

    def assert_invalid(self, config: dict, expected_text: str) -> None:
        """Проверить, что настройки отклоняются и в сообщении есть expected_text."""
        with self.assertRaises(ConfigError) as context:
            validate_config(config)
        self.assertIn(expected_text, str(context.exception))

    def test_default_config_is_valid(self) -> None:
        """Файл data/config.json из проекта проходит проверку."""
        self.assertEqual(self.config["firewall_test"]["test_port"], 80)
        self.assertIsNone(self.config["antivirus_test"]["eicar_dir"])
        self.assertTrue(DEFAULT_CONFIG_PATH.endswith(os.path.join("data", "config.json")))

    def test_load_from_path(self) -> None:
        """Настройки читаются из указанного файла."""
        config = copy.deepcopy(self.config)
        config["network"]["tcp_port"] = 8443
        path = self.write_file(json.dumps(config))
        self.assertEqual(load_config(path)["network"]["tcp_port"], 8443)

    def test_missing_section(self) -> None:
        """Отсутствующий раздел называется в сообщении."""
        config = copy.deepcopy(self.config)
        del config["antivirus_test"]
        self.assert_invalid(config, "antivirus_test")

    def test_missing_key(self) -> None:
        """Отсутствующий ключ называется полностью."""
        config = copy.deepcopy(self.config)
        del config["firewall_test"]["host"]
        self.assert_invalid(config, "firewall_test.host")

    def test_wrong_type(self) -> None:
        """Строка вместо числа отклоняется."""
        config = copy.deepcopy(self.config)
        config["network"]["tcp_timeout_s"] = "3"
        self.assert_invalid(config, "network.tcp_timeout_s")

    def test_bool_is_not_number(self) -> None:
        """true не принимается как число."""
        config = copy.deepcopy(self.config)
        config["network"]["ping_timeout_s"] = True
        self.assert_invalid(config, "network.ping_timeout_s")

    def test_port_range(self) -> None:
        """Порт вне диапазона 1–65535 отклоняется."""
        config = copy.deepcopy(self.config)
        config["firewall_test"]["control_port"] = 70000
        self.assert_invalid(config, "firewall_test.control_port")

    def test_empty_host_list(self) -> None:
        """Пустой список узлов отклоняется."""
        config = copy.deepcopy(self.config)
        config["network"]["ru_hosts"] = []
        self.assert_invalid(config, "network.ru_hosts")

    def test_eicar_dir_string_allowed(self) -> None:
        """eicar_dir может быть строкой."""
        config = copy.deepcopy(self.config)
        config["antivirus_test"]["eicar_dir"] = "/home/user"
        validate_config(config)

    def test_same_ports_rejected(self) -> None:
        """Тестовый и контрольный порты должны различаться."""
        config = copy.deepcopy(self.config)
        config["firewall_test"]["test_port"] = config["firewall_test"]["control_port"]
        self.assert_invalid(config, "firewall_test.test_port")

    def test_poll_interval_not_greater_than_timeout(self) -> None:
        """Интервал опроса не может превышать таймаут M4."""
        config = copy.deepcopy(self.config)
        config["antivirus_test"]["poll_interval_s"] = 60
        self.assert_invalid(config, "poll_interval_s")

    def test_root_not_object(self) -> None:
        """Корень JSON должен быть объектом."""
        self.assert_invalid([], "корневой элемент")

    def test_file_not_found(self) -> None:
        """Отсутствующий файл — ConfigError с путём."""
        path = os.path.join(self.tmp_dir, "nope.json")
        with self.assertRaises(ConfigError) as context:
            load_config(path)
        self.assertIn("файл не найден", str(context.exception))
        self.assertIn(path, str(context.exception))

    def test_bad_json(self) -> None:
        """Ошибка синтаксиса JSON — ConfigError с номером строки."""
        path = self.write_file('{\n  "network": ,\n}')
        with self.assertRaises(ConfigError) as context:
            load_config(path)
        self.assertIn("строке 2", str(context.exception))


if __name__ == "__main__":
    unittest.main()
