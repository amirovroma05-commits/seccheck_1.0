"""Выбор адаптера под текущую операционную систему."""

from __future__ import annotations

import sys

from adapters.astra import AstraAdapter
from adapters.base import SystemAdapter


class UnsupportedPlatformError(Exception):
    """Программа запущена на ОС, для которой нет адаптера."""


def create_adapter() -> SystemAdapter:
    """Создать адаптер для текущей ОС.

    На любом Linux используется AstraAdapter: на других дистрибутивах программа
    работает для разработки, а предупреждение выводит интерфейс по os_info().
    Сюда же позже добавится ветка для Windows (adapters/windows.py).
    """
    if sys.platform.startswith("linux"):
        return AstraAdapter()
    raise UnsupportedPlatformError(
        "ОС «{}» не поддерживается: программа рассчитана на Astra Linux SE".format(
            sys.platform))
