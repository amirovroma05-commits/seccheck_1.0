#!/bin/sh
# Удаление SecCheck: каталог /opt/seccheck и команда /usr/local/bin/seccheck.
# Запуск: sudo ./uninstall.sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Нужны права root: sudo ./uninstall.sh" >&2
    exit 1
fi

rm -rf /opt/seccheck
rm -f /usr/local/bin/seccheck

echo "SecCheck удалён."
