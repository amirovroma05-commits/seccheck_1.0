#!/bin/sh
# Установка SecCheck в /opt/seccheck, настройки в /etc/seccheck, команда seccheck.
# Запуск: sudo ./install.sh. Повторный запуск обновляет установленную версию;
# существующий файл настроек /etc/seccheck/config.json никогда не перезаписывается.
set -eu

INSTALL_DIR=/opt/seccheck
CONFIG_DIR=/etc/seccheck
CONFIG_FILE=$CONFIG_DIR/config.json
WRAPPER=/usr/local/bin/seccheck

if [ "$(id -u)" -ne 0 ]; then
    echo "Нужны права root: sudo ./install.sh" >&2
    exit 1
fi

# Каталог, где лежит этот скрипт (исходники программы).
SRC_DIR=$(cd "$(dirname "$0")" && pwd)
for required in main.py products.json config.json; do
    if [ ! -f "$SRC_DIR/$required" ]; then
        echo "Не найден $SRC_DIR/$required: запускайте скрипт из каталога проекта" >&2
        exit 1
    fi
done

# Удалить старую версию программы целиком, чтобы не осталось файлов, которых больше нет
# в проекте. Настройки лежат отдельно, в /etc/seccheck, и здесь не затрагиваются.
rm -rf "$INSTALL_DIR"

# Каталог и файлы принадлежат root и доступны на запись только ему.
# config.json в /opt/seccheck — образец настроек для сравнения после обновления.
install -d -o root -g root -m 755 "$INSTALL_DIR"
for file in "$SRC_DIR"/*.py "$SRC_DIR/products.json" "$SRC_DIR/config.json"; do
    install -o root -g root -m 644 "$file" "$INSTALL_DIR/"
done

# Команда seccheck: обёртка, запускающая main.py системным интерпретатором.
install -d -o root -g root -m 755 "$(dirname "$WRAPPER")"
printf '#!/bin/sh\nexec /usr/bin/python3 %s/main.py "$@"\n' "$INSTALL_DIR" > "$WRAPPER"
chown root:root "$WRAPPER"
chmod 755 "$WRAPPER"

# Настройки: создать при первой установке, существующие не трогать.
install -d -o root -g root -m 755 "$CONFIG_DIR"
CONFIG_OK=yes
if [ ! -e "$CONFIG_FILE" ]; then
    install -o root -g root -m 644 "$SRC_DIR/config.json" "$CONFIG_FILE"
    echo "Создан файл настроек $CONFIG_FILE"
else
    echo "Файл настроек $CONFIG_FILE уже есть, он не изменён."
    # Проверить существующий файл той же функцией, что и программа.
    # -I: не брать модули из текущего каталога и пользовательских путей; -B: без __pycache__.
    if ! /usr/bin/python3 -I -B -c '
import sys
sys.path.insert(0, sys.argv[1])
import common
try:
    common.load_config(sys.argv[2])
except ValueError as exc:
    print(exc, file=sys.stderr)
    sys.exit(1)
' "$INSTALL_DIR" "$CONFIG_FILE"; then
        CONFIG_OK=no
        echo "В файле настроек есть ошибки (см. выше). Возможно, в новой версии появились" >&2
        echo "новые ключи: сравните $CONFIG_FILE с образцом $INSTALL_DIR/config.json" >&2
        echo "и исправьте файл, иначе программа не запустится." >&2
    fi
fi

echo "SecCheck установлен в $INSTALL_DIR. Запуск: sudo seccheck"
if [ "$CONFIG_OK" = no ]; then
    exit 1
fi
