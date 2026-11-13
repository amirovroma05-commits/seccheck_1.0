# SecCheck

Консольная программа контроля работоспособности антивируса (АВ) и межсетевого экрана (МЭ)
в Linux с systemd. Выполняет четыре проверки и выводит отчёт:

1. подключение к интернету;
2. наличие МЭ и АВ;
3. работоспособность МЭ (по тестовому правилу);
4. работоспособность АВ (по тестовому файлу EICAR).

Требования: Python 3.7 или новее, только стандартная библиотека. Права root нужны для
чтения правил МЭ (проверка 2); без них программа работает, но предупреждает об этом.

## Запуск при разработке

```bash
chmod +x main.py        # один раз после клонирования
sudo ./main.py          # интерактивное меню
./main.py --help
./main.py --version
```

## Установка и обновление

```bash
sudo ./install.sh                 # установка в /opt/seccheck и команда seccheck
sudo seccheck                     # запуск после установки
git pull && sudo ./install.sh     # обновление
sudo ./uninstall.sh               # удаление
```

`install.sh` копирует файлы `*.py` в `/opt/seccheck` (владелец root, каталог 755,
файлы 644) и создаёт обёртку `/usr/local/bin/seccheck`. При повторном запуске старая
версия удаляется целиком и устанавливается заново.

### Почему программа ставится в каталог, доступный на запись только root

Программа запускается от root. Если бы её файлы лежали в каталоге, куда может писать
обычный пользователь (например, в домашнем каталоге), любой процесс этого пользователя,
в том числе вредоносный, мог бы незаметно изменить код. При следующем запуске через `sudo`
изменённый код выполнился бы с правами root, то есть получилось бы повышение привилегий.
Поэтому установленная копия лежит в `/opt/seccheck`, а она и обёртка
`/usr/local/bin/seccheck` принадлежат root и закрыты от записи остальным. Обёртка
вызывает интерпретатор по полному пути `/usr/bin/python3`, чтобы его нельзя было подменить
через `PATH`. Запуск из рабочей копии (`sudo ./main.py`) годится только для разработки.

## Подготовка стенда

Команды даны для дистрибутивов на базе Debian (`apt`). В других дистрибутивах установите
те же пакеты своим пакетным менеджером. Имена пакетов и служб проверьте в своей системе.

### ClamAV с проверкой при доступе (clamonacc)

```bash
sudo apt install clamav clamav-daemon
sudo systemctl stop clamav-freshclam && sudo freshclam && sudo systemctl start clamav-freshclam
```

В `/etc/clamav/clamd.conf` добавьте:

```
OnAccessIncludePath /tmp
OnAccessPrevention yes
OnAccessExcludeUname clamav
```

- `OnAccessIncludePath /tmp` — проверка 4 создаёт тестовый файл во временном каталоге
  (`/tmp`), clamonacc следит только за указанными каталогами;
- `OnAccessPrevention yes` — блокировать доступ к заражённому файлу, а не только писать
  в журнал;
- `OnAccessExcludeUname clamav` — не проверять действия самого ClamAV.

Перезапустите службы:

```bash
sudo systemctl restart clamav-daemon
sudo systemctl enable --now clamav-clamonacc   # имя службы проверьте: systemctl list-unit-files | grep clam
```

### ufw

```bash
sudo apt install ufw
sudo ufw allow ssh        # если работаете по SSH, иначе после включения связь пропадёт
sudo ufw enable
sudo ufw status verbose
```

## Тестовое правило МЭ (для проверки 3)

Проверка 3 подключается к узлу `ya.ru` на разрешённый порт 443 и на порт 80, который
должен быть запрещён правилом. Узел и порты заданы константами в начале
`check_firewall.py` (`FW_HOST`, `CONTROL_PORT`, `TEST_PORT`). Правило запрещает все
исходящие соединения на порт 80, поэтому после проверки его нужно удалить.

ufw:

```bash
sudo ufw deny out 80/tcp           # создать
sudo ufw delete deny out 80/tcp    # удалить
```

nftables (если ufw не используется):

```bash
sudo nft add table inet seccheck
sudo nft add chain inet seccheck output '{ type filter hook output priority 0; }'
sudo nft add rule inet seccheck output tcp dport 80 counter drop
sudo nft delete table inet seccheck    # удалить
```

Без правила проверка 3 честно покажет `FAIL`: МЭ пропустил соединение.
