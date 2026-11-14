"""M3. Проверка работоспособности межсетевого экрана (МЭ).

Отвечает на вопрос: блокирует ли МЭ соединение, запрещённое его правилом.

Программа сама создаёт временное тестовое правило — запрет исходящих TCP-соединений
на IP:test_port с меткой seccheck-test — и подключается к тому же IP и порту дважды:
до правила (порт должен быть доступен) и после (соединение должно быть заблокировано).
Между подключениями меняется только наличие правила, поэтому блокировка у провайдера
на результат не влияет. Правило удаляется в любом случае (finally), в том числе после
Ctrl+C, SIGTERM и SIGHUP.

Правило добавляется через утилиту самого МЭ (для ufw — командой ufw), а не напрямую
в nft или iptables. Если МЭ выключен, его правило не применится, соединение пройдёт,
и результат честно будет FAIL. Правило, добавленное прямо в nft, сработало бы и при
выключенном МЭ.
"""

import signal
import socket
import time
from typing import Dict, List, Optional, Tuple

import check_presence
from common import FAIL, INCONCLUSIVE, OK, is_root, run_cmd

# Настройки берутся из секции "firewall_test" файла настроек (см. README.md, «Настройки»):
#   host      — узел для подключений;
#   test_port — порт, на который запрещает соединения тестовое правило;
#   timeout_s — таймаут одного подключения и одной внешней команды (ufw, systemctl), с.

# Метка тестового правила: по ней правило можно найти вручную (`sudo ufw status`),
# если программу завершили принудительно (kill -9) и она не успела его удалить.
RULE_LABEL = "seccheck-test"

# Тестовое правило ufw: запрет исходящих TCP-соединений на {ip}:{port} с меткой.
UFW_TEST_RULE = ["deny", "out", "to", "{ip}", "port", "{port}", "proto", "tcp",
                 "comment", RULE_LABEL]

# Команды тестового правила для МЭ, которые программа умеет проверять:
# id продукта из products.json -> команды. В аргументах «{ip}» и «{port}» заменяются
# адресом узла и тестовым портом.
#
# Команды хранятся только здесь, а не в products.json: тот файл можно подменить флагом
# --products, а программа работает от root. Из products.json берётся только id, по которому
# выбирается одна из этих заранее заданных команд.
#
# Поведение ufw проверено по исходному коду ufw 0.36.1 (Ubuntu):
#   add — `ufw insert 1 ...`: правило встаёт первым, раньше разрешающих правил пользователя.
#     Иначе его перекрыло бы, например, правило пользователя «allow out» на этот порт.
#     `ufw prepend` не подходит: он появился только в ufw 0.36, а в Astra Linux ufw 0.35.
#   add_when_empty — `insert 1` завершается ошибкой «Invalid position '1'», если правил
#     для IPv4 ещё нет. Тогда правило добавляется обычной командой и всё равно стоит первым.
#   empty_error — начало текста этой ошибки.
#   exists_text — если такое правило уже есть (совпадают адрес, порт и направление, даже
#     при другом действии или комментарии), ufw ничего не меняет и пишет «Skipping ...».
#     Это правило пользователя: программа его не добавляла и удалять не будет.
#   delete — удаление по полному описанию вместе с меткой. ufw удаляет только правило,
#     совпадающее во всём, включая комментарий seccheck-test, поэтому правила пользователя
#     (в том числе его `deny out 80/tcp`) не затрагиваются.
# При выключенном ufw обе команды тоже работают: меняются только сохранённые правила
# (ufw отвечает «Rules updated»), в netfilter они не попадают.
# TODO(стенд): подтвердить те же ответы ufw 0.35 на Astra Linux.
TEST_RULE_COMMANDS = {
    "ufw": {
        "add": ["ufw", "insert", "1"] + UFW_TEST_RULE,
        "add_when_empty": ["ufw"] + UFW_TEST_RULE,
        "empty_error": "Invalid position",
        "exists_text": "Skipping",
        "delete": ["ufw", "delete"] + UFW_TEST_RULE,
    },
}


def fill_command(cmd: List[str], ip: str, port: int) -> List[str]:
    """Подставить IP-адрес и порт вместо «{ip}» и «{port}» в аргументы команды."""
    result = []
    for arg in cmd:
        result.append(arg.replace("{ip}", ip).replace("{port}", str(port)))
    return result


def first_line(code: int, stdout: str, stderr: str) -> str:
    """Первая строка сообщения команды: из stderr, иначе из stdout, иначе код возврата."""
    lines = stderr.strip().splitlines() or stdout.strip().splitlines()
    if lines:
        return lines[0]
    return "код " + str(code)


def choose_firewall(products: List[dict], timeout_s: float) -> Tuple[Optional[dict], List[str]]:
    """Шаг 2. Выбрать МЭ для проверки.

    Перебрать продукты вида "firewall" из products.json по порядку и вернуть первый,
    который найден в системе (так же, как в M2) и для которого заданы команды
    в TEST_RULE_COMMANDS. Вернуть (продукт или None, подробности). В подробности попадают
    найденные МЭ, для которых способ проверки не задан.
    """
    details = []
    for product in products:
        if "firewall" not in product["kinds"]:
            continue
        found, _stopped, _evidence = check_presence.detect_product(product, timeout_s)
        if not found:
            continue
        if product["id"] in TEST_RULE_COMMANDS:
            return product, details
        details.append("{}: способ проверки не задан".format(product["name"]))
    return None, details


def connect(ip: str, port: int, timeout_s: float) -> Tuple[Optional[OSError], int]:
    """Подключиться к ip:port. Вернуть (None или ошибка подключения, время в мс)."""
    start = time.monotonic()
    try:
        connection = socket.create_connection((ip, port), timeout=timeout_s)
    except OSError as exc:
        return exc, int((time.monotonic() - start) * 1000)
    connection.close()
    return None, int((time.monotonic() - start) * 1000)


def add_test_rule(commands: dict, ip: str, port: int,
                  timeout_s: float) -> Tuple[bool, List[str]]:
    """Шаг 5. Добавить тестовое правило. Вернуть (добавлено ли, подробности)."""
    cmd = fill_command(commands["add"], ip, port)
    code, stdout, stderr = run_cmd(cmd, timeout=timeout_s)
    if code != 0 and commands["empty_error"] in stderr:
        # Список правил пуст: обычное добавление поставит правило первым.
        cmd = fill_command(commands["add_when_empty"], ip, port)
        code, stdout, stderr = run_cmd(cmd, timeout=timeout_s)
    details = ["Тестовое правило: " + " ".join(cmd)]
    if code != 0:
        details.append("Ошибка добавления: " + first_line(code, stdout, stderr))
        return False, details
    if commands["exists_text"] in stdout:
        details.append("Такое правило уже есть в настройках МЭ, программа его не меняет")
        return False, details
    return True, details


def remove_test_rule(commands: dict, ip: str, port: int,
                     timeout_s: float) -> Tuple[List[str], List[str]]:
    """Шаг 7. Удалить тестовое правило. Вернуть (подробности, предупреждения).

    Предупреждения (если удалить не удалось) содержат точную команду удаления
    и печатаются всегда, а не только с -v: в МЭ осталось правило программы.
    """
    cmd = fill_command(commands["delete"], ip, port)
    code, stdout, stderr = run_cmd(cmd, timeout=timeout_s)
    if code == 0:
        return ["Удаление правила: выполнено"], []
    details = ["Удаление правила: не выполнено ({})".format(first_line(code, stdout, stderr))]
    warnings = ["Внимание: тестовое правило не удалено, удалите его вручную:",
                "sudo " + " ".join(cmd)]
    return details, warnings


def describe_refusal(error: OSError, timeout_s: float) -> List[str]:
    """Тип отказа в подключении после добавления правила (для подробностей)."""
    if isinstance(error, PermissionError):
        # Ядро сразу возвращает EPERM, если исходящий пакет отброшен netfilter.
        # TODO(стенд): подтвердить на стенде с включённым ufw.
        return ["Тип отказа: соединение запрещено локальным МЭ (EPERM)"]
    if isinstance(error, ConnectionRefusedError):
        return ["Тип отказа: соединение отклонено (правило REJECT)"]
    if isinstance(error, socket.timeout):
        return ["Тип отказа: соединение не установлено за {} с (вероятно, правило DROP)"
                .format(timeout_s),
                "Таймаут указывает на МЭ: до добавления правила порт был доступен"]
    return ["Тип отказа: другая ошибка ({})".format(error)]


def raise_on_signal(signum: int, _frame: object) -> None:
    """Обработчик SIGTERM и SIGHUP на время, пока существует тестовое правило.

    По умолчанию эти сигналы (kill, закрытие терминала) завершают процесс сразу, без
    выполнения finally, и правило осталось бы в МЭ. Обработчик превращает сигнал
    в исключение SystemExit: оно, как KeyboardInterrupt от Ctrl+C, проходит через finally
    (правило удаляется), а затем завершает программу с кодом 128 + номер сигнала.
    """
    raise SystemExit(128 + signum)


def replace_signal_handlers(handlers: Dict[int, object]) -> Dict[int, object]:
    """Установить обработчики сигналов {номер сигнала: обработчик}.

    Вернуть прежние обработчики в том же виде, чтобы потом их восстановить.
    """
    previous = {}
    for signum, handler in handlers.items():
        previous[signum] = signal.signal(signum, handler)
    return previous


def run(cfg: dict, products: List[dict]) -> Tuple[str, List[str], List[str]]:
    """Выполнить проверку M3. Вернуть (статус, краткие строки, подробности).

    cfg — секция "firewall_test" файла настроек;
    products — список продуктов, загруженный load_products() при старте программы.
    """
    host = cfg["host"]
    test_port = cfg["test_port"]
    timeout_s = cfg["timeout_s"]

    # Шаг 1. Добавить правило МЭ может только root.
    if not is_root():
        return INCONCLUSIVE, ["не определена — нужны права root"], []

    # Шаг 2. Выбрать МЭ, который программа умеет проверять.
    product, details = choose_firewall(products, timeout_s)
    if product is None:
        return INCONCLUSIVE, ["не определена — не найден МЭ, который программа умеет проверять"
                              ], details
    details.append("Проверяемый МЭ: " + product["name"])
    commands = TEST_RULE_COMMANDS[product["id"]]

    # Шаг 3. Разрешить имя в IPv4 один раз: оба подключения идут на один и тот же адрес.
    try:
        addresses = socket.getaddrinfo(host, test_port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        details.append("Ошибка разрешения имени: {}".format(exc))
        return INCONCLUSIVE, ["не определена — имя узла {} не разрешается (DNS)".format(host)
                              ], details
    ip = addresses[0][4][0]
    details.append("Узел: {} ({})".format(host, ip))

    # Шаг 4. Контрольное подключение до правила. Если порт закрыт и без нашего правила,
    # вывод о работе МЭ сделать нельзя.
    error, ms = connect(ip, test_port, timeout_s)
    if error is not None:
        details.append("До правила: порт {} недоступен ({})".format(test_port, error))
        return INCONCLUSIVE, ["не определена — тестовый порт недоступен ещё до проверки"
                              ], details
    details.append("До правила: порт {} доступен ({} мс)".format(test_port, ms))

    # Шаги 5–7. Пока правило может существовать, SIGTERM и SIGHUP превращаются
    # в исключение (raise_on_signal), чтобы finally успел удалить правило. Ctrl+C (SIGINT)
    # обрабатывается стандартным обработчиком Python: он и так даёт KeyboardInterrupt.
    saved_handlers = replace_signal_handlers({signal.SIGINT: signal.default_int_handler,
                                              signal.SIGTERM: raise_on_signal,
                                              signal.SIGHUP: raise_on_signal})
    # added: True — правило добавлено, False — не добавлено, None — добавление прервано
    # (Ctrl+C или сигнал во время команды), и правило могло появиться.
    added = None  # type: Optional[bool]
    finished = False  # проверка дошла до конца без исключения
    try:
        added, rule_details = add_test_rule(commands, ip, test_port, timeout_s)
        details.extend(rule_details)
        if not added:
            status = INCONCLUSIVE
            brief = ["не определена — не удалось добавить тестовое правило"]
        else:
            # Шаг 6. Подключиться ещё раз, теперь при действующем правиле.
            error, ms = connect(ip, test_port, timeout_s)
            if error is None:
                details.append("После правила: порт {}: соединение установлено ({} мс)".format(
                    test_port, ms))
                status = FAIL
                brief = ["запрещённое соединение не заблокировано",
                         "Проверьте, что межсетевой экран включён"]
            else:
                details.append("После правила: порт {}: соединение не установлено ({} мс)"
                               .format(test_port, ms))
                details.extend(describe_refusal(error, timeout_s))
                status = OK
                brief = ["запрещённое соединение заблокировано"]
        finished = True
    finally:
        # Шаг 7. Удалить правило при любом исходе. На время удаления сигналы
        # игнорируются: повторный Ctrl+C не должен прервать удаление и оставить правило.
        replace_signal_handlers({signal.SIGINT: signal.SIG_IGN,
                                 signal.SIGTERM: signal.SIG_IGN,
                                 signal.SIGHUP: signal.SIG_IGN})
        warnings = []  # type: List[str]
        if added is not False:
            removal_details, warnings = remove_test_rule(commands, ip, test_port, timeout_s)
            details.extend(removal_details)
        replace_signal_handlers(saved_handlers)
        if not finished:
            # Проверку прервали: результата не будет, поэтому предупреждение о неудалённом
            # правиле печатается сразу, затем исключение идёт дальше.
            for line in warnings:
                print(line)

    # Шаг 8. Итог определён на шаге 6; предупреждение о неудалённом правиле — под ним.
    return status, brief + warnings, details
