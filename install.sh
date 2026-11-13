#!/bin/sh
# Установка SecCheck в /opt/seccheck и создание команды seccheck.
# Запуск: sudo ./install.sh. Повторный запуск обновляет установленную версию.
set -eu

INSTALL_DIR=/opt/seccheck
WRAPPER=/usr/local/bin/seccheck

if [ "$(id -u)" -ne 0 ]; then
    echo "Нужны права root: sudo ./install.sh" >&2
    exit 1
fi

# Каталог, где лежит этот скрипт (исходники программы).
SRC_DIR=$(cd "$(dirname "$0")" && pwd)
for required in main.py products.json; do
    if [ ! -f "$SRC_DIR/$required" ]; then
        echo "Не найден $SRC_DIR/$required: запускайте скрипт из каталога проекта" >&2
        exit 1
    fi
done

# Удалить старую версию целиком, чтобы не осталось файлов, которых больше нет в проекте.
rm -rf "$INSTALL_DIR"

# Каталог и файлы принадлежат root и доступны на запись только ему.
install -d -o root -g root -m 755 "$INSTALL_DIR"
for file in "$SRC_DIR"/*.py "$SRC_DIR/products.json"; do
    install -o root -g root -m 644 "$file" "$INSTALL_DIR/"
done

# Команда seccheck: обёртка, запускающая main.py системным интерпретатором.
install -d -o root -g root -m 755 "$(dirname "$WRAPPER")"
printf '#!/bin/sh\nexec /usr/bin/python3 %s/main.py "$@"\n' "$INSTALL_DIR" > "$WRAPPER"
chown root:root "$WRAPPER"
chmod 755 "$WRAPPER"

echo "SecCheck установлен в $INSTALL_DIR. Запуск: sudo seccheck"
