# SecCheck — техническое задание

## 0. Контекст

Курсовая работа «Методы и средства защиты информации в компьютерных сетях», МТУСИ.
По методичке программа должна содержать пять модулей:

1. проверка наличия подключения к интернету;
2. проверка наличия установленных межсетевого экрана (МЭ) и антивируса (АВ);
3. проверка работоспособности МЭ;
4. проверка работоспособности АВ (тестовый файл EICAR);
5. вывод результатов.

Методичка разрешает консольный интерфейс. Примеры в ней на C# под Windows: мы их не копируем,
но покрываем те же функции. Кроме кода нужны блок-схемы всех алгоритмов (ГОСТ 19.701-90).
Поэтому алгоритмы ниже записаны пошагово, и код обязан им соответствовать.

## 1. Область работ

**Делаем сейчас**
- Astra Linux Special Edition 1.7 и 1.8.
- Консольный интерфейс: интерактивное меню и неинтерактивный режим с флагами.
- Python 3.7+, только стандартная библиотека.

**Не делаем сейчас, но архитектура должна это позволять**
- Windows: потом добавится `adapters/windows.py` с той же сигнатурой методов.
- Оконный интерфейс: потом добавится `ui/gui.py` поверх того же `core/controller.py`.

**На других Linux** (Ubuntu, Debian) программа должна запускаться для разработки
с предупреждением «ОС не Astra Linux, результаты могут отличаться», а не падать.

## 2. Стенд (для понимания контекста)

- Виртуальная машина с Astra Linux SE. Версия Python: 1.7 — 3.7; 1.8 — новее (проверить
  `python3 --version`).
- Запуск программы от root (`sudo`). Без root часть проверок урезается (см. модули).
- В Astra SE может быть включена ЗПС (замкнутая программная среда) и мандатный контроль.
  Программа запускается как скрипт `python3 main.py`, в бинарник (PyInstaller) не собираем.
- Средства защиты на стенде: ClamAV с `clamonacc` (on-access) и `ufw`. Опционально пробные
  Dr.Web для Linux или Kaspersky Endpoint Security для Linux (KESL).
- Тестовое правило МЭ создаёт автор вручную по командам, которые печатает
  `main.py --print-fw-rule`.

## 3. Архитектура

Слои (каждый слой обращается только к нижнему):

```
ui/ (CLI)  →  core/controller.py  →  checks/M1..M5  →  adapters/ (AstraAdapter)  →  ОС
                     │                    │
                core/store.py        data/config.json, data/products.json
```

- `ui/` только ввод и вывод. Ничего не знает об ОС.
- `core/controller.py` запускает проверки, кладёт результаты в `ResultStore`, ловит
  неожиданные исключения модуля и превращает их в `CheckResult(status=ERROR)`.
- `checks/` — логика проверок. Не печатает, не читает stdin, не вызывает subprocess.
- `adapters/` — всё, что зависит от ОС: запуск команд, чтение `/proc`, `/etc/os-release`.

> Пакет называется `adapters`, а **не** `platform`: пакет `platform` перекрыл бы модуль
> стандартной библиотеки `platform` и сломал бы импорты.

### Структура проекта

```
seccheck/
├── CLAUDE.md
├── main.py                  # точка входа: разбор аргументов, запуск ui.cli
├── core/
│   ├── __init__.py
│   ├── models.py            # Status, Level, CheckResult, DetectedProduct, CommandResult
│   ├── store.py             # ResultStore
│   ├── config.py            # загрузка и проверка config.json и products.json
│   └── controller.py        # Controller
├── checks/
│   ├── __init__.py
│   ├── network.py           # M1
│   ├── presence.py          # M2
│   ├── netfilter.py         # разбор вывода nft / iptables (чистые функции, для M2)
│   ├── firewall.py          # M3
│   ├── antivirus.py         # M4
│   └── report.py            # M5
├── adapters/
│   ├── __init__.py
│   ├── base.py              # SystemAdapter (абстрактный класс)
│   ├── astra.py             # AstraAdapter
│   └── factory.py           # create_adapter()
├── ui/
│   ├── __init__.py
│   ├── cli.py               # меню, флаги, коды возврата
│   └── render.py            # форматирование CheckResult в текст, цвета ANSI
├── data/
│   ├── config.json
│   └── products.json
├── reports/                 # создаётся при первом отчёте, в .gitignore
├── docs/
│   ├── SPEC.md              # этот файл
│   └── STAND.md             # инструкция подготовки стенда (этап 7)
└── tests/
    ├── fake_adapter.py      # FakeAdapter с заранее заданными ответами
    ├── fixtures/            # примеры вывода nft, iptables, systemctl, ufw, dpkg
    └── test_*.py
```

## 4. Модель данных (`core/models.py`)

```python
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

class Status(Enum):
    OK = "OK"                     # проверка пройдена
    WARNING = "WARNING"           # работает частично / есть замечания
    FAIL = "FAIL"                 # средство защиты не сработало / отсутствует
    INCONCLUSIVE = "INCONCLUSIVE" # вывод сделать нельзя (нет сети, недоступна цель)
    NOT_RUN = "NOT_RUN"           # проверку не запускали
    ERROR = "ERROR"               # сбой программы или нехватка прав

class Level(Enum):                # уровень обнаружения продукта (M2)
    NOT_FOUND = 0
    INSTALLED = 1                 # есть пакет или файлы
    RUNNING = 2                   # служба активна или процесс запущен
    ACTIVE = 3                    # подтверждено, что защита включена

@dataclass
class CheckResult:
    check_id: str                 # "M1".."M4"
    title: str
    status: Status
    summary: str                  # одна строка для меню
    details: list = field(default_factory=list)   # list[str], строки для отчёта
    data: dict = field(default_factory=dict)      # машинно-читаемые данные для JSON и M3
    started_at: datetime = None
    duration_ms: int = 0

@dataclass
class DetectedProduct:
    product_id: str
    name: str
    kinds: list                   # ["antivirus"], ["firewall"] или оба
    level: Level
    evidence: list                # ["пакет clamav-daemon установлен", "процесс clamonacc"]
    verified_profile: bool        # из поля verified профиля

@dataclass
class CommandResult:
    returncode: int               # -1 не найдена, -2 таймаут, -3 нет права на запуск
    stdout: str
    stderr: str
    not_found: bool = False
    timed_out: bool = False
```

Аннотации `list[str]` в полях dataclass не используем: в Python 3.7 dataclass читает
аннотации, и это работает только благодаря `from __future__ import annotations`. Чтобы
не рисковать, пиши `list` / `dict` и уточняй тип в комментарии, либо `typing.List[str]`.

## 5. Адаптер (`adapters/base.py`, `adapters/astra.py`)

```python
class SystemAdapter(ABC):
    def os_info(self) -> dict: ...            # {"name", "version", "is_astra", "pretty"}
    def is_root(self) -> bool: ...
    def hostname(self) -> str: ...
    def run(self, cmd: list, timeout: float) -> CommandResult: ...
    def ping(self, host: str, timeout_s: int) -> bool: ...
    def services(self) -> dict: ...           # {"clamav-daemon": "active", ...}
    def processes(self) -> set: ...           # {"clamd", "clamonacc", ...}
    def packages(self) -> set: ...            # установленные пакеты
    def path_exists(self, path: str) -> bool: ...
    def netfilter_dump(self) -> dict: ...     # сырые выводы, см. ниже
```

Реализация `AstraAdapter`:

| Метод | Как |
|---|---|
| `os_info` | `/etc/os-release` (`NAME`, `VERSION_ID`, `PRETTY_NAME`); `is_astra` = `ID=astra` или есть `/etc/astra_version` (если есть, взять версию оттуда) |
| `is_root` | `os.geteuid() == 0` |
| `run` | `subprocess.run(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True, timeout=…, env={**os.environ, "LC_ALL": "C"})`; `errors="replace"`; `FileNotFoundError` → `not_found=True`; `TimeoutExpired` → `timed_out=True`; `PermissionError` (нет бита x, запрет ЗПС) → код `-3`. Без `shell=True` |
| `ping` | `ping -c 1 -W <timeout_s> <host>`, успех = returncode 0 |
| `services` | `systemctl list-units --type=service --all --no-legend --plain --no-pager`; колонки: UNIT LOAD ACTIVE SUB…; ключ — имя без `.service` |
| `processes` | читать `/proc/<pid>/comm` для всех числовых каталогов `/proc`; ошибки чтения пропускать (процесс завершился) |
| `packages` | `dpkg-query -W -f '${Package}\t${db:Status-Status}\n'`, брать только `installed` |
| `netfilter_dump` | `{"nft": run(["nft","list","ruleset"]), "iptables_version": run(["iptables","-V"]), "iptables": run(["iptables","-S"]), "iptables_legacy": run(["iptables-legacy","-S"])}` |

Тонкости:
- `nft list ruleset` без root выдаёт `Operation not permitted`. Адаптер возвращает результат
  как есть, а решение принимает модуль (статус «нужны права root»).
- `iptables -V` печатает `(nf_tables)` или `(legacy)`. Правила legacy через `nft` не видны,
  поэтому смотрим оба источника.
- Вывод `systemctl`, `ufw`, `dpkg` локализован, поэтому всегда `LC_ALL=C`.
- Каждый метод кэширует результат на время одного запуска M2 (метод `refresh()` сбрасывает
  кэш), чтобы не вызывать `systemctl` по 10 раз.

`tests/fake_adapter.py`: `FakeAdapter(SystemAdapter)`, все ответы задаются в конструкторе.
`run()` берёт ответ из словаря по `tuple(cmd)`.

## 6. Модули проверок

Каждый модуль — функция `run_mX(adapter, config, store) -> CheckResult` (M5 устроен иначе,
см. ниже). Алгоритмы пронумерованы так же, как блоки блок-схем в записке.

### M1. Проверка подключения к интернету (`checks/network.py`)

Узлы делятся на две группы, чтобы отличить полный доступ от ограниченного (белые списки
мобильных операторов, блокировки). ICMP часто режется, поэтому решение принимается по TCP.

Алгоритм:
1. Прочитать из config группы `ru_hosts` и `foreign_hosts`.
2. Для каждого узла: `ping` (результат только информационный).
3. Для каждого узла: TCP-подключение к `tcp_port` (443) с таймаутом `tcp_timeout_s`
   через `socket.create_connection`. Ошибку DNS (`socket.gaierror`) запомнить отдельно.
4. Группа доступна, если хотя бы один её узел ответил по TCP.
5. Ни одна группа не доступна → `FAIL` «Нет подключения к интернету». Если все ошибки —
   DNS, добавить в details «не работает разрешение имён (DNS)».
6. Доступна одна группа → `WARNING` «Доступ к интернету ограничен: доступны только
   российские / только зарубежные узлы».
7. Доступны обе → `OK` «Подключение к интернету есть».
8. В details по каждому узлу: ICMP да/нет, TCP да/нет, время подключения в мс.
   Если TCP работает, а ICMP нет ни у одного узла, добавить «ICMP блокируется».

TCP-подключения делать последовательно (так проще объяснить), общий таймаут ограничен
конфигом.

### M2. Обнаружение МЭ и АВ (`checks/presence.py`, `checks/netfilter.py`)

На Linux нет единого реестра средств защиты (как Центр безопасности Windows), поэтому:
(а) сопоставление фактов о системе с профилями из `products.json`;
(б) универсальная проверка: есть ли фильтрация в netfilter, через который работают
практически все сетевые фильтры Linux.

Алгоритм:
1. Собрать факты через адаптер: службы, процессы, пакеты.
2. Взять следующий профиль из `products.json` с `"os": "linux"`.
3. Проверить признаки `detect`: хотя бы один пакет или файл → `INSTALLED`; служба в
   состоянии `active` или процесс из списка → `RUNNING`.
4. Признаков нет → перейти к шагу 7.
5. Если у профиля есть `active_check` и уровень ≥ `INSTALLED`, выполнить его
   (типы ниже). Успех → `ACTIVE`. Нужны права root, а их нет → оставить уровень и
   добавить в evidence «проверка активности требует прав root».
6. Добавить `DetectedProduct` в список.
7. Профили закончились? Нет → шаг 2.
8. Netfilter: разобрать `netfilter_dump()` (см. ниже) → признак «фильтрация включена» и
   источник (`nftables`, `iptables-legacy`, `iptables-nft`).
9. Итоговый статус:
   - есть АВ с `ACTIVE` и (МЭ с `ACTIVE` или фильтрация netfilter включена) → `OK`;
   - что-то найдено, но не всё активно → `WARNING` с перечислением, чего не хватает;
   - не найдено ни АВ, ни МЭ, фильтрации нет → `FAIL`;
   - без root и netfilter не прочитан → в details «правила МЭ не прочитаны: нужны права root».
10. В `result.data` положить `{"products": [...], "netfilter": {...},
    "firewall_present": bool, "antivirus_present": bool}`: эти данные читает M3.

Типы `active_check`:
- `{"type": "command", "cmd": [...], "expect_regex": "...", "needs_root": true}` —
  команда завершилась с кодом 0 и stdout совпал с regex (`re.MULTILINE`);
- `{"type": "process", "name": "clamonacc"}` — процесс запущен;
- `{"type": "service", "name": "kesl"}` — служба `active`.

Разбор netfilter (`checks/netfilter.py`, чистые функции, тесты на fixtures):
- **nft**: найти цепочки с `type filter hook input|output|forward`; фильтрация включена,
  если у такой цепочки `policy drop` или в любой цепочке таблицы есть правило с действием
  `drop` или `reject`. Вернуть число правил и список «значимых» строк (до 10) для details.
- **iptables -S / iptables-legacy -S**: строки `-P INPUT DROP` / `-P OUTPUT DROP` /
  `-P FORWARD DROP` или любые `-j DROP` / `-j REJECT`. Цепочки `ufw-*` — признак ufw.
- Пустой вывод или только `-P ... ACCEPT` → фильтрации нет.

### M3. Проверка работоспособности МЭ (`checks/firewall.py`)

Подход методички «обратиться к запрещённому ресурсу» в России ненадёжен: зарубежный ресурс
может быть заблокирован провайдером, и программа ошибочно решит, что МЭ работает. Поэтому:
- **тестовая цель** — узел `firewall_test.host` на порту `firewall_test.test_port`,
  исходящие соединения на который запрещены правилом, созданным проверяющим заранее
  (по умолчанию `ya.ru:80`);
- **контрольная цель** — **тот же IP-адрес** на разрешённом порту
  `firewall_test.control_port` (`ya.ru:443`).

В конфиге задан один узел `host`, поэтому имя разрешается один раз, оба подключения идут
на один IP, отличается только порт. Провайдерскую блокировку по IP это исключает.

Алгоритм:
1. Прочитать из config `firewall_test.host`, `control_port`, `test_port`, `timeout_s`.
2. Если в store есть результат M2 и `firewall_present` ложно, добавить в details
   «МЭ не обнаружен модулем M2, тест носит информационный характер». Если M2 не
   выполнялся, написать «M2 не выполнялся».
3. Разрешить имя `host` в IPv4 (`socket.getaddrinfo(..., AF_INET)`).
   Ошибка → `INCONCLUSIVE` «не удалось разрешить имя».
4. Подключиться к `IP:control_port` (таймаут `timeout_s`). Не удалось → `INCONCLUSIVE`
   «контрольная цель недоступна, вывод о работе МЭ сделать нельзя».
5. Подключиться к `IP:test_port` (таймаут `timeout_s`).
6. Соединение установлено → `FAIL` «МЭ пропустил соединение, которое должен был
   запретить. Правило не создано или МЭ не работает» + подсказка про `--print-fw-rule`.
7. Не установлено → определить тип отказа и вернуть `OK`:
   - `PermissionError` / `errno.EPERM` — «соединение запрещено локальным МЭ»: ядро сразу
     возвращает EPERM, когда исходящий пакет отброшен netfilter. Самое сильное
     доказательство (`# TODO(стенд): подтвердить на Astra с ufw deny out`);
   - `ConnectionRefusedError` — «соединение отклонено (правило REJECT)»;
   - `socket.timeout` — «соединение не установлено за N с (вероятно, правило DROP)»,
     в details пометка «таймаут косвенно указывает на МЭ: контрольная цель на том же
     адресе доступна».
8. В details: IP, порты, тип отказа, время.

`--print-fw-rule` печатает (ничего не выполняя) команды для тестового правила
и для его удаления:

```
# ufw
sudo ufw deny out 80/tcp
sudo ufw delete deny out 80/tcp
# nftables (если ufw не используется)
sudo nft add table inet seccheck
sudo nft add chain inet seccheck output '{ type filter hook output priority 0; }'
sudo nft add rule inet seccheck output tcp dport 80 counter drop
sudo nft delete table inet seccheck
```

Порт (здесь `80`) берётся из `firewall_test.test_port`. Правило блокирует все исходящие на этот порт: это проще и не
зависит от смены IP узла, на время теста этого достаточно.

### M4. Проверка работоспособности АВ (`checks/antivirus.py`)

Резидентная защита (on-access) должна среагировать на создание тестового файла EICAR.

Алгоритм:
1. Собрать строку EICAR из частей, хранящихся в коде раздельно (никогда целиком).
2. Создать временный каталог: `config.eicar_dir`, если задан, иначе
   `tempfile.mkdtemp(prefix="seccheck_")`.
3. Записать `eicar_test.txt`: `open` → `write` → `flush` → `os.fsync` → `close`
   (многие АВ на Linux проверяют файл при закрытии после записи через fanotify).
4. `PermissionError` или `OSError` при записи/закрытии → `OK` «АВ заблокировал запись».
5. Подождать `poll_interval_s` (1 с).
6. Файл не существует → `OK` «АВ удалил файл или переместил в карантин за N с».
7. Попробовать прочитать файл. `PermissionError` → `OK` «АВ заблокировал доступ к файлу».
   Содержимое отличается от записанного → `OK` «АВ изменил файл (лечение/очистка)».
8. Прошло меньше `eicar_timeout_s` → шаг 5.
9. Иначе → `FAIL` «Резидентная защита не среагировала за T с».
10. В `finally`: удалить файл и каталог (если удаление не удалось, предупреждение в details
    с путём).
11. В details: путь, время реакции, способ реакции.

Нюансы, которые нужно вывести в details при `FAIL`:
- ClamAV `clamonacc` проверяет только каталоги из `OnAccessIncludePath`; блокирует доступ
  только при `OnAccessPrevention yes`, иначе только пишет в журнал. Подсказка: «проверьте
  OnAccessIncludePath и OnAccessPrevention в clamd.conf или задайте eicar_dir».
- Если M2 не нашёл ни одного АВ, добавить это в details.

Тест без настоящего АВ: в unittest поток-«антивирус» удаляет файл через 2 с → ожидается `OK`;
без потока, с `eicar_timeout_s=2` → `FAIL`.

### M5. Отчёт (`checks/report.py`)

`build_report(store, adapter_info) -> Report`, где Report хранит заголовок и упорядоченные
результаты M1–M4. Отсутствующая в store проверка получает `Status.NOT_RUN` и summary
«не выполнялась».

- Заголовок: название и версия программы, дата и время, имя ПК, ОС (`PRETTY_NAME` и
  версия Astra), версия Python, запуск от root да/нет.
- `to_text()` — человекочитаемый отчёт (без ANSI-цветов).
- `to_json()` — тот же отчёт в JSON (`ensure_ascii=False`, `indent=2`).
- `save(dir)` — `reports/report_ГГГГММДД_ЧЧММСС.txt` и `.json`, каталог создать при
  необходимости. Вернуть пути.

## 7. Консольный интерфейс (`ui/cli.py`, `ui/render.py`)

Интерактивное меню (повторяет кнопки из методички):

```
SecCheck 0.1 · Astra Linux SE 1.7.5 · запуск от root: да

  1  Проверка подключения к интернету
  2  Проверка наличия МЭ и АВ
  3  Проверка работоспособности МЭ
  4  Проверка работоспособности АВ
  5  Выполнить все проверки
  6  Вывести и сохранить отчёт
  0  Выход

Выберите пункт: _
```

Вывод результата:

```
[  OK  ] M1  Подключение к интернету есть
         ya.ru        ICMP: да   TCP 443: да  (23 мс)
         ...
```

- Метки статусов: `[  OK  ]` зелёный, `[ WARN ]` жёлтый, `[ FAIL ]` красный,
  `[  ??  ]` INCONCLUSIVE серый, `[ ---- ]` NOT_RUN серый, `[ ERR  ]` красный.
- ANSI-цвета отключаются, если stdout не терминал, задан `--no-color` или переменная
  окружения `NO_COLOR`.
- Во время ожидания M4 печатать прогресс в одну строку: `Ожидание реакции АВ… 12/30 с`
  (через `\r`, только если stdout — терминал). Для этого M4 принимает необязательный
  callback `on_progress(elapsed, total)`, который передаёт UI. Модуль сам не печатает.
- Ширина вывода до 100 символов: результаты пойдут на скриншоты в записку.
- Без root при старте предупреждение одной строкой, какие проверки будут ограничены.
- `Ctrl+C` в меню и во время проверки обрабатывается: файл EICAR удаляется, выход
  с кодом 130.

Флаги (`argparse`):

| Флаг | Действие |
|---|---|
| без флагов | интерактивное меню |
| `--all` | M1→M2→M3→M4, затем отчёт в консоль и в `reports/` |
| `--check M1,M3` | только указанные проверки (+ отчёт) |
| `--json` | вместе с `--all`/`--check`: отчёт в JSON в stdout, без цветов и меню |
| `--no-color` | без ANSI-цветов |
| `--config PATH` | другой config.json |
| `--print-fw-rule` | напечатать команды тестового правила МЭ и выйти |
| `--version` | версия |

Коды возврата для `--all` / `--check`: `0` все OK; `1` есть WARNING или INCONCLUSIVE;
`2` есть FAIL; `3` есть ERROR. Берётся самый тяжёлый. Это позволяет запускать программу
по расписанию (cron, systemd timer) — пункт для раздела «Пути развития».

## 8. Данные

### `data/config.json` (значения по умолчанию)

```json
{
  "network": {
    "ru_hosts": ["ya.ru", "vk.com"],
    "foreign_hosts": ["example.com", "github.com"],
    "tcp_port": 443,
    "tcp_timeout_s": 3,
    "ping_timeout_s": 2
  },
  "firewall_test": {
    "host": "ya.ru",
    "control_port": 443,
    "test_port": 80,
    "timeout_s": 3
  },
  "antivirus_test": {
    "eicar_dir": null,
    "eicar_timeout_s": 30,
    "poll_interval_s": 1
  },
  "report": {
    "dir": "reports"
  }
}
```

`core/config.py` проверяет наличие ключей и типы. При ошибке — понятное сообщение
с указанием ключа, без трассировки.

### `data/products.json`

```json
{
  "schema_version": 1,
  "products": [
    {
      "id": "clamav",
      "name": "ClamAV",
      "vendor": "Cisco Talos (open source)",
      "kinds": ["antivirus"],
      "os": "linux",
      "verified": true,
      "detect": {
        "packages": ["clamav-daemon", "clamav"],
        "services": ["clamav-daemon"],
        "processes": ["clamd"],
        "files": ["/usr/sbin/clamd"]
      },
      "active_check": {"type": "process", "name": "clamonacc"},
      "notes": "ACTIVE = запущен clamonacc (проверка при доступе). Один clamd без clamonacc — только RUNNING."
    },
    {
      "id": "drweb",
      "name": "Dr.Web для Linux",
      "vendor": "Доктор Веб",
      "kinds": ["antivirus", "firewall"],
      "os": "linux",
      "verified": false,
      "detect": {
        "packages": [],
        "services": ["drweb-configd"],
        "processes": ["drweb-configd"],
        "files": ["/opt/drweb.com/bin/drweb-ctl"]
      },
      "active_check": {"type": "command", "cmd": ["drweb-ctl", "appinfo"],
                       "expect_regex": "(?i)spider", "needs_root": false},
      "notes": "drweb-configd и drweb-ctl подтверждены документацией. Пакеты и regex активности уточнить на стенде."
    },
    {
      "id": "kesl",
      "name": "Kaspersky Endpoint Security для Linux",
      "vendor": "Лаборатория Касперского",
      "kinds": ["antivirus", "firewall"],
      "os": "linux",
      "verified": false,
      "detect": {
        "packages": ["kesl"],
        "services": ["kesl"],
        "processes": [],
        "files": ["/opt/kaspersky/kesl/bin/kesl-control"]
      },
      "active_check": {"type": "command", "cmd": ["kesl-control", "--get-task-list"],
                       "expect_regex": "(?i)file.?threat.?protection.*(started|running)",
                       "needs_root": true},
      "notes": "Служба kesl и kesl-control подтверждены документацией. Имя пакета и формат вывода --get-task-list уточнить на стенде."
    },
    {
      "id": "ufw",
      "name": "UFW (Uncomplicated Firewall)",
      "vendor": "Canonical (open source)",
      "kinds": ["firewall"],
      "os": "linux",
      "verified": true,
      "detect": {
        "packages": ["ufw"],
        "services": ["ufw"],
        "processes": [],
        "files": ["/usr/sbin/ufw"]
      },
      "active_check": {"type": "command", "cmd": ["ufw", "status"],
                       "expect_regex": "^Status: active", "needs_root": true},
      "notes": "Служба ufw — oneshot: active означает, что правила загружены при старте."
    },
    {
      "id": "firewalld",
      "name": "firewalld",
      "vendor": "Red Hat (open source)",
      "kinds": ["firewall"],
      "os": "linux",
      "verified": true,
      "detect": {
        "packages": ["firewalld"],
        "services": ["firewalld"],
        "processes": ["firewalld"],
        "files": ["/usr/bin/firewall-cmd"]
      },
      "active_check": {"type": "command", "cmd": ["firewall-cmd", "--state"],
                       "expect_regex": "^running", "needs_root": false}
    },
    {
      "id": "vipnet_client",
      "name": "ViPNet Client для Linux",
      "vendor": "ИнфоТеКС",
      "kinds": ["firewall"],
      "os": "linux",
      "verified": false,
      "detect": {
        "packages": ["vipnetclient"],
        "services": ["vipnetclient"],
        "processes": [],
        "files": []
      },
      "notes": "Все имена — предположение, проверить на стенде."
    }
  ]
}
```

Secret Net LSP и Dallas Lock добавить после проверки имён на стенде. В профиле
`gufw` не нужен: это графическая оболочка над ufw.

## 9. Пример текстового отчёта

```
Результаты тестирования средств защиты
SecCheck 0.1 · 2026-11-20 14:32:05
ПК: astra-vm · Astra Linux SE 1.7.5 · Python 3.7.3 · запуск от root: да

1. [OK]   Подключение к интернету есть
2. [OK]   МЭ и АВ: ClamAV — защита активна; ufw — активен; фильтрация netfilter включена
3. [OK]   МЭ работает: соединение 87.250.250.242:80 запрещено локальным МЭ (EPERM)
4. [OK]   АВ работает: файл удалён или помещён в карантин через 2 с

Подробности
...
```

## 10. Тестирование

- `unittest`, запуск `python3 -m unittest discover -s tests -v`.
- Тесты не требуют root, сети и установленных АВ/МЭ: системные данные через `FakeAdapter`
  и файлы `tests/fixtures/`.
- Сеть в тестах M1/M3 — локальные сокеты на `127.0.0.1`: слушающий сокет — «доступный
  порт», свободный порт — «отказ». Тест таймаута — адрес, который не отвечает
  (с коротким таймаутом), или подмена функции подключения.
- Fixtures для netfilter: пустой ruleset; ufw на iptables-nft; nft с `policy drop`;
  iptables-legacy с `-j REJECT`; ruleset только с `policy accept`. Пока нет реальных
  выводов со стенда, сделать правдоподобные и пометить `# TODO(стенд): заменить реальным`.
- Тест, что строка EICAR целиком не встречается ни в одном `.py` файле проекта.

## 11. Порядок работы

Каждый этап заканчивается зелёными тестами и остановкой для проверки автором.

1. **Каркас.** Структура каталогов, `models.py`, `store.py`, `config.py` с проверкой,
   `adapters/base.py`, `AstraAdapter` (`os_info`, `is_root`, `run`), `FakeAdapter`,
   `controller.py`, меню-заглушка в `ui/cli.py`. `.gitignore` (`reports/`, `__pycache__/`).
2. **M1** + тесты + вывод в меню.
3. **M4** + прогресс в консоли + тесты с потоком-«антивирусом».
4. **M2**: остальные методы `AstraAdapter`, `netfilter.py`, `presence.py`,
   `products.json` + тесты на fixtures.
5. **M3** + `--print-fw-rule` + тесты.
6. **M5** + `--all`, `--check`, `--json`, коды возврата + тесты.
7. **Документы для записки**: `docs/STAND.md` (подготовка стенда: установка ClamAV,
   настройка `clamonacc` с `OnAccessIncludePath` и `OnAccessPrevention yes`, включение
   ufw, создание и удаление тестового правила, порядок демонстрации на защите) и
   `docs/ALGORITHMS.md` (словесное описание каждого алгоритма для пояснительной записки,
   в той же нумерации шагов, что здесь).

## 12. Критерии готовности

- `sudo python3 main.py --all` на Astra SE выполняет все проверки и сохраняет отчёт.
- Без root программа не падает и в отчёте объясняет, что ограничено.
- Ни одна внешняя команда не может повесить программу (таймауты везде).
- Строка EICAR целиком не встречается в исходниках; тестовый файл удаляется даже после
  Ctrl+C.
- Все тесты проходят на Python 3.7.
- Код каждого модуля проверок соответствует пошаговому алгоритму из раздела 6.

## 13. Известные ограничения (для раздела «Анализ результатов»)

- Обнаружение продуктов зависит от полноты `products.json`; универсальная проверка
  netfilter показывает, есть ли фильтрация, но не называет продукт.
- Фильтры на eBPF/XDP работают в обход netfilter и правилами nft не видны.
- M3 проверяет одно правило на исходящий трафик, а не всю политику МЭ.
- M4 проверяет реакцию резидентного модуля на эталонный тестовый файл, а не способность
  обнаруживать реальные угрозы.
- Решение M1 основано на доступности выбранных узлов; на точность влияют блокировки
  и режим белых списков.
