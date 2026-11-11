"""Адаптеры операционной системы: всё, что зависит от ОС (команды, /proc, /etc/os-release).

Пакет называется adapters, а не platform, чтобы не перекрыть модуль стандартной
библиотеки platform.
"""

from __future__ import annotations
