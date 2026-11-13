#!/bin/sh
# Удаление SecCheck: каталог /opt/seccheck и команда /usr/local/bin/seccheck.
# Настройки в /etc/seccheck сохраняются.
# Запуск: sudo ./uninstall.sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Нужны права root: sudo ./uninstall.sh" >&2
    exit 1
fi

rm -rf /opt/seccheck
rm -f /usr/local/bin/seccheck

echo "SecCheck удалён."
# Настройки не удаляются: они могли быть изменены вручную.
if [ -d /etc/seccheck ]; then
    echo "Настройки сохранены в /etc/seccheck. Удалить их вручную: sudo rm -r /etc/seccheck"
fi
