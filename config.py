# Aurora v1.0 — конфигурация ядра.
# Всё, что меняется между деплоями: пути, порты, источники ключей, режимы.

import base64
import binascii
import ipaddress
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import uuid
from collections import deque

VERSION = "2.0.0"
VERSION_NAME = "Кот-хозяин"
APP_NAME = "Aurora"

# История версий для вкладки «Версии» (v, имя, дата).
# ВАЖНО: без дублей — иначе вкладка показывает одну версию несколько раз.
VERSION_HISTORY = (
    ("2.0.0", "Кот-хозяин", "28.11.2026"),
    ("1.10.28", "Кот-диспетчер", "23.11.2026"),
    ("1.10.27", "Кот-создатель", "23.11.2026"),
    ("1.10.26", "Кот-смотритель", "19.11.2026"),
    ("1.10.25", "Кот-кран", "18.11.2026"),
    ("1.10.24", "Кот-выключатель", "18.11.2026"),
    ("1.10.23", "Кот-обновщик", "18.11.2026"),
    ("1.10.22", "Кот-маскировщик", "18.11.2026"),
    ("1.10.21", "Кот-дебаг", "17.11.2026"),
    ("1.10.20", "Кот-дизайнер", "17.11.2026"),
    ("1.10.19", "Кот-коммутатор", "16.11.2026"),
    ("1.10.18", "Кот-диагност", "30.10.2026"),
    ("1.10.17", "Кот-диагност", "28.10.2026"),
    ("1.10.15", "Кот-диагност", "28.10.2026"),
    ("1.10.14", "Кот-диагност", "26.10.2026"),
    ("1.10.13", "Кот-постоянный", "13.10.2026"),
    ("1.10.12", "Кот-переключатель", "12.10.2026"),
    ("1.10.11", "Кот-чистый", "12.10.2026"),
    ("1.10.10", "Кот-компас", "12.10.2026"),
    ("1.10.9", "Кот-проводник", "12.10.2026"),
    ("1.10.8", "Кот-подхват", "12.10.2026"),
    ("1.10.7", "Кот-оберег", "10.10.2026"), ("1.10.6", "Кот-переключатель", "09.10.2026"), ("1.10.5", "Кот-обновщик", "08.10.2026"),
    ("1.10.4", "Кот-подсеть", "07.10.2026"),
    ("1.10.3", "Кот-прибирщик", "07.10.2026"),
    ("1.10.2", "Кот-тополог", "06.10.2026"),
    ("1.10.1", "Кот-вольный", "05.10.2026"),
    ("1.10.0", "Кот-вольный", "05.10.2026"),
    ("1.9.3", "Кот-глашатай", "25.09.2026"),
    ("1.9.2", "Кот-починщик", "25.09.2026"),
    ("1.9.1", "Кот-крепость", "25.09.2026"),
    ("1.9.0", "Кот-правозащитник", "24.09.2026"),
    ("1.8.0", "Кот-именитый", "24.09.2026"),
    ("1.7.0", "Кот-дипломат", "24.09.2026"),
    ("1.6.0", "Кот-банкир", "24.09.2026"),
    ("1.5.0", "Кот в мешке", "24.09.2026"),
    ("1.4.0", "Подписки", "22.09.2026"),
    ("1.3.1", "Мур-апдейт", "22.09.2026"),
    ("1.3.0", "Mesh", "22.09.2026"),
    ("1.2.0", "Windows-fix", "19.09.2026"),
    ("1.1.0", "Свежая рыба", "19.09.2026"),
)

# Описания версий для вкладки «Версии» (v -> текст). Показываются в панели.
VERSION_NOTES = {
    "2.0.0": "🐾 Чистая сборка 2.0.0: подписки, платежи, лицензии, политика «Кот в законе» и подключение к головному серверу удалены полностью. Всё, что раньше требовало подписки, доступно сразу; меш работает локально; сохранены прокси, VLESS для дома, TG-WS, WARP/MASQUE, DNS и бэкапы. Linux и Windows-зеркало синхронны.",
    "1.10.28": "Кот-диспетчер взял канал под присмотр 🐾. Четыре новые возможности во вкладке «Сервис». Авто-переключение резерва: диспетчер оценивает здоровье VLESS-пула, MASQUE и WARP и сам переводит трафик на живой резерв, когда основной умирает, а когда основной оживает — возвращает обратно; ручной выбор канала ставит паузу, чтобы диспетчер не спорил с владельцем, все переключения видны в журнале. TG-уведомления: опциональный бот сообщает о переключениях канала, смене выходного IP, мёртвом пуле ключей и доступном обновлении; токен и chat_id хранятся в шифрованных настройках или env, в журнал и API не попадают, повторные события гасятся кулдауном. Экспорт клиентских конфигов: готовый профиль для подключения к этому серверу в v2rayN (ссылка), sing-box (JSON) и Clash.Meta (YAML) с QR и пометкой, какой канал сейчас активен на сервере. Плановый бэкап: архив по расписанию тем же шифрованным ZIP, хранение N последних копий с ротацией, скачивание и восстановление из панели. Новая дорожная карта проекта — в ROADMAP.md.",
    "1.10.27": "Кот-создатель убирает главную боль MASQUE: конфиг теперь можно СОЗДАТЬ прямо в панели 🐾. Раньше были только загрузка готового JSON/Clash-YAML и получение с сайта-генератора. Кнопка «➕ Создать конфиг» генерирует свежую пару EC P-256 на чистом stdlib (без зависимости от cryptography), регистрирует публичный ключ через Cloudflare WARP API, выбирает живой MASQUE-эндпоинт, применяет конфиг, поднимает mihomo и проверяет выходной IP. Сайт-генератор остался запасным вариантом. Починено скачивание mihomo: свежие релизы v1.19.x перешли на версионированные zip/gz, а старый URL .exe отдавал 404 — чистая установка теперь работает. Проба выхода больше не зависит от внешнего curl: используется stdlib-запрос через локальный mixed-port, curl оставлен запасным. Исправлен «Выходной IP -»: панель берёт свежий IP активного MASQUE/WARP из сохранённых конфигов, даже если xray молчит или панель только что перезапустилась. Клиентский трафик на мастере переведён с мёртвого WireGuard WARP на живой MASQUE через локальный SOCKS mihomo — Instagram и ipify снова открываются.",
    "1.10.26": "Кот-смотритель принёс в панель вкладку «Сервис» с четырьмя полезными приборами. Диагностика: одна кнопка проверяет порт xray, прямой выход, выход через прокси, выходной IP, DNS, IPv6, TG-WS, ру-сегмент и оба резервных канала — с временем каждой проверки и итогом. Замер скорости: ping, загрузка и отдача через тот же порт, что у владельца, с историей последних замеров. Автопроверка ключей: расписание (раз в N минут) с журналом событий, чтобы мёртвые ключи не ждали утреннего нажатия кнопки. Бэкап: настройки, пул ключей и конфиги WARP/MASQUE упаковываются в ZIP, зашифрованный паролем владельца (scrypt + ChaCha20-Poly1305), и восстанавливаются на этой или другой машине; порты и учётные данные панели в архив не попадают, чтобы восстановление не могло закрыть доступ к серверу.",
    "1.10.25": "Кот-кран добавил выключатель внешнего VLESS-Reality :8443 на вкладку «Внешний доступ»: выключенный inbound исчезает из xray и порт закрывается, включённый — возвращается. Настройки по-прежнему берутся из env AURORA_VLESS_*, кнопка только гасит/поднимает сам inbound.",
    "1.10.24": "Кот-выключатель добавил в панель выключатели внешнего резервного канала (MASQUE/mihomo) и Telegram WS-прокси. На серверах, где внешний выход и TG не нужны, их теперь можно погасить одной кнопкой: выключенный канал останавливает mihomo, выключенный TG-WS останавливает прокси и не поднимает его. Заодно в Windows-сборку дотянуты обработчики MASQUE (вкладка там раньше отвечала ошибкой).",
    "1.10.23": "Кот-обновщик починил доставку новых модулей при автообновлении: в список доставляемых файлов добавлен masque.py, а логика новых модулей теперь понимает файлы в корне архива (раньше такие молча пропускались, и узел падал на ModuleNotFoundError после обновления). Уже обновившиеся узлы с прошлым релизом починим доставкой masque.py.",
    "1.10.22": "Кот-маскировщик добавил транспорт MASQUE для резерва Cloudflare WARP: в части сетей чистый WireGuard блокируется (нет ответов на handshake), а MASQUE (mihomo) проходит. В мастере настройки появился шаг «Резервный канал (WARP)» с выбором WireGuard/MASQUE и проверкой выходного IP, в панели — вкладка MASQUE для загрузки и смены конфигов. Старый WARP-раздел на мастере убран, чтобы не путаться.",
    "1.10.21": "Кот-дебаг починил UI после WARP-действий: в обработчиках висел неопределённый refresh(), из-за чего в консоли ReferenceError, а пользователь видел ложный «сервер не ответил». Теперь вызов loadState(true).",
    "1.10.20": "Кот-дизайнер вернул публичной сборке её собственный интерфейс: компактная иконная навигация, строка поиска и выпадающие группы из мастер-раскладки откачены (e4741a2/5b5b8d4/66c075f). Linux и Windows снова зеркальны, тесты UI-гейта проходят.",
    "1.10.19": "Кот-коммутатор: выбор другого WARP-конфига теперь реально переключает канал. Раньше у WARP-выхода был постоянный тег, поэтому xray.json оставался со старым адресом, а кнопка отвечала «уже на WARP» — список менялся, трафик нет. Теперь конфиг пересобирается и применяется сразу.",
    "1.10.18": "Кот-диагност: проверка подписи mesh-entitlements и лицензии, восстановлен cooldown Cloudflare 429, выровнены Linux/Windows и updater.",
    "1.10.17": "Кот-диагност: восстановлено исправление обработки ответа «Канал на WARP». postJSON парсит ответ строго через text+json.parse.",
    "1.10.15": "Кот-диагност: исправлена обработка ответа «Канал на WARP». При сетевом сбое UI больше не показывает ложное «сервер не ответил», если ответ уже получен, и чётче сообщает причину отказа.",
    "1.10.14": "Кот-диагност перестал отвечать одной фразой на разные поломки. Кнопка «Канал на WARP» теперь говорит причину: конфиг WARP не загружен (Aurora его не генерирует — его загружает владелец), не найден xray.exe или xray не принял конфиг. Сервер проверяет бинарь и конфиг ДО записи xray.json и откатывает файл, если xray не поднялся, поэтому следующий синк больше не считает канал переключённым. Причина отказа пишется в журнал, ошибка видна 8 секунд. В Windows-сборке download_xray.ps1 теперь кладёт xray в bin рядом с run.py — раньше он попадал на уровень выше, и переключение падало уже после записи конфига. Честно: WARP-конфиг по-прежнему готовит и загружает человек, сборка его не создаёт.",
    "1.10.13": u"Rezhim Cloudflare WARP Vsegda teper po-nastoyashchemu vsegda: kot bolshe ne soskalkzyvaet na VPN-klyuchi pri avtosinxronizacii, rotacii i proverke zhivogo kanala. Cloudflare ne obyazan otdayat vyhodnoi IP tem servisam, kotorymi my ego meryaem, i ranshe watchdog prinimal eto za smert kanala. Pereklyuchenie na WARP peresobiraet config, esli kanala eshche net, i chestno govorit uzhe na WARP, esli on uzhe vklyuchen. Zadno poyavilis knopka zagruzki configov WARP i relei-tunnel mesh-seti s publikaciej VLESS-profilya v 8-m pole HELLO.",
    "1.10.12": "Кот-переключатель довел до конца то, что началось в прошлых выпусках: загрузка конфига Cloudflare WARP теперь действительно открывает диалог выбора файла. Причина была не в сервере, а в кнопке - обработчик клика перехватывал и отменял искусственный клик по скрытому полю, поэтому окно выбора открывалось и сразу исчезало. Второе: кнопка «Канал на WARP» теперь действительно переключает канал - раньше она честно отвечала «такого канала нет», потому что резервный канал WARP появляется в конфигурации только при сборке под него, теперь система пересобирает конфигурацию под выбранный канал. И третье: панель перестала дёргать проверку обновлений каждые несколько секунд, поэтому список версий не перерисовывался сам и не мешал. Честно: у канала WARP выходной адрес показывается прочерком, если WARP не отвечает нашим проверочным сервисам, - это нормальное поведение Cloudflare, канал при этом живой.",
    "1.10.10": "Кот-компас показывает, куда идти, и пускает туда, откуда пришли. Во-первых, блок WARP больше не спрятан на вкладке «Ключи» - у него своя вкладка в меню, поэтому кнопки видны сразу, а не после неудачного поиска по другим вкладкам. Во-вторых, панель теперь принимает не один адрес: появилась переменная окружения AURORA_EXTRA_HOSTS со списком дополнительных адресов через точки с запятой. Раньше сервер знал только свой адрес, и если открыть панель по адресу Tailnet или по другому имени, она честно отвечала «host not allowed» и страница не работала вообще. Список явный - гейт не расширяется сам, только то, что вписал оператор. Честно: без правильного адреса в этой переменной панель по-прежнему не откроется - это осознанно, чтобы чужие адреса не подходили автоматически.",
    "1.10.10": "Кот-компас показывает, куда идти, и пускает туда, откуда пришли. Во-первых, блок WARP больше не спрятан на вкладке «Ключи» - у него своя вкладка в меню, поэтому кнопки видны сразу, а не после неудачного поиска по другим вкладкам. Во-вторых, панель теперь принимает не один адрес: появилась переменная окружения AURORA_EXTRA_HOSTS со списком дополнительных адресов через точки с запятой. Раньше сервер знал только свой адрес, и если открыть панель по адресу Tailnet или по другому имени, она честно отвечала «host not allowed» и страница не работала вообще. Список явный - гейт не расширяется сам, только то, что вписал оператор. Честно: без правильного адреса в этой переменной панель по-прежнему не откроется - это осознанно, чтобы чужие адреса не подходили автоматически.",
    "1.10.9": "Кот-проводник починил три вещи, которые молчали по своей. Первая: загрузка конфигуров Cloudflare WARP доходила до сервера, но проверка падала с TypeError - код звал ожидание порта с аргументом, которого в этой функции никогда не было, поэтому проба не работала вообще ни разу. Вторая и главная: сервер не подтягивал ключи, потому что сгенерированный конфиг xray не проходил проверку - в правиле приватных адресов стоял geoip:private, а файла geoip.dat в обычной сборке нет, он лежит только в Windows-версии. Теперь приватные подсети перечислены явно, собрать конфиг нечем, и прокси снова едет на живых ключах. Третья: у проверки ключей не было полосы прогресса - сервер молчал, владелец не видел, на каком этапе процесс. Теперь видно и сообщение, и проценты, и разбор по статусам. И маленькая правка в самой панели: блок WARP падал на середине и не дорисовывал таблицу конфигов и кнопки, из-за чего они выглядели нерабочими. Честно: две последние ошибки были в браузере, не в прокси.",
    "1.10.8": "Кот-подхват починил загрузку конфигов Cloudflare WARP. Кнопка «Загрузить» открывала выбор файла, но после выбора не произошолось ничего: обработчик, который должен был прочитать файл и отправить его на сервер, был написан, но к нему не прикрепляли событие выбора файла. Панель молчала, и владелец считал, что загрузка не работает. Теперь выбор файла действительно доходит до сервера, и в списке конфигов сразу виден выходной IP. Честно: причина была не в сервере — приём конфигов работал вёсь это время, молчал только браузер.",
    "1.10.7": "Кот-оберег больше не даёт прокси умереть от собственной "
                "статистики: правило для служебного порта теперь идёт первым "
                "и трафик к нему больше не заворачивается в прямой выход, "
                "из-за чего xray дозванивался сам в себя и съедал все "
                "файловые дескрипторы. Раньше один запрос статистики ронял "
                "канал за считанные секунды. Заодно переключение на WARP "
                "больше не ждёт выходной IP (Cloudflare WARP его не обязан "
                "отдавать), а смена канала перестала мучить его четырьмя "
                "пробами подряд: туннель проверяется сразу, и живой канал "
                "остаётся живым даже когда IP-сервисы молчат.",
    "1.10.5": "Кот-обновщик научился довозить себя целиком: если в новом "
                "релизе появился модуль, которого на сервере ещё нет, обновление "
                "теперь доставляет и его, а не только те файлы, что были в списке "
                "на момент запуска. Раньше новый модуль молча пропускался, и узел "
                "падал при первом же старте с ошибкой импорта.",
    "1.10.4":
        "Кот-подсеть привёл игровой туннель к настоящему виду. Раньше "
        "адаптер был написан под мёртвый API WinTun и не поднимался ни "
        "разу: поставляемая библиотека оказалась WinTun 1.x, где нет "
        "функций, которые звал код. Теперь версия API определяется по "
        "настоящей библиотеке, обратный путь relay → узел на Windows "
        "действительно пишет в адаптер, тред чтения не умирает, а сам "
        "адаптер открывается по имени и не создаётся молча. Плюс новая "
        "настройка game_tun: подсеть игровых узлов включается только "
        "явно, по умолчанию выключена. Честно: полный проход пакета "
        "через адаптер измерить не удалось — сессия WinTun на этой "
        "машине не открывается ни при одной из пяти проверенных "
        "конвенций вызова, поэтому Windows-ветка отказывает честно, "
        "а не делает вид, что поднялась.",
    "1.10.3":
        "Кот-прибирщик вынес мусор из пула. Мёртвые ключи больше не"
        "копятся: чистка смотрит на метку смерти у ЛЮБОГО источника,"
        "а не только у github, поэтому подвисшие висяки уходят сами, а"
        "не месяцами. Связь между узлами меш-сети теперь терпеливая:"
        "туннель берёт порт из настроек и подождёт, если порт ещё занят"
        "после перезапуска, вместо того чтобы молча не подняться."
        "Имя узла, которое записано, теперь то же, что показывает"
        "панель — переименований-призраков больше нет.",
    "1.10.2": "Прилипчивое имя узла. Котик перестал забывать, кто он: раньше при "
            "каждом старте меш выдавал узлу новое имя, и вместо «Полосотом-1262» "
            "в топологии плыли «Тёплый-Кот» и «Пушистый-Кот». Теперь узел "
            "объявляет своё устойчивое имя и держит его, а случайное имя выдаётся "
            "только при реальном конфликте. Заодно в клиентскую сборку переехал "
            "игровой контур и адаптер туннеля — раньше в ней их просто не было.",

    "1.9.4":
        "Привратник закрыл дверь для лишних: лицензия PRO приходит с головного сервера, расширение браузера и блок рекламы открыты уже на триале, а обход «Белого списка» и безлимиты — только по подписке. Появился релей-туннель между узлами меш-сети, устройство теперь и есть купленный ключ, а панель честно показывает тариф, срок и трафик по ключу.",
    "1.9.3": "Глашатай выходит на площадь: тарифы, оплата и продление теперь прямо в Telegram-боте. Браузерное "
                                  "расширение стало дружелюбнее, а в панели — понятный состав тарифов и дополнительных возможностей.",
    "1.9.2": "Починщик подлатал авто-обновление: теперь оно аккуратнее переносит файлы и не спотыкается на разных "
                                  "дисках. Для Windows появился установщик Aurora-Setup — быстрый старт без лишних движений.",
    "1.9.1": "Крепость укрепила стены: релизы и хранилище под надёжной защитой, приглашения в сеть — безопаснее, "
                                  "права доступа — строже. Первый запуск стал понятным мастером, а интерфейс — чище и спокойнее.",
    "1.9.0": "Правозащитник обновил политику и правила. Некоторые разделы теперь открываются только после команды "
                                  "головного сервера — так в сети больше порядок.",
    "1.8.0": "Именитый сам выбирает имя и вступает в сеть. Появился тестовый узел, а вкладки «Меш» и «Магазин» "
                                  "стали видны с головного сервера.",
    "1.7.0": "Дипломат вынес политику на первую страницу с историей версий, спрятал секреты под замкок и добавил "
                                  "раздел «Защита». Русский сегмент и регионы — под рукой.",
    "1.6.0": "Банкир построил меш-сеть и магазин тарифов: статистика, топология, маршруты, безопасность — всё в "
                                  "одном месте.",
    "1.5.0": "Кот в мешке принёс подписки с оплатой и продлением, счётчик трафика, лимиты и управление "
                                  "устройствами.",
    "1.4.0": "Появились тарифы free/basic/prem, маскирование ключей и внешний защищённый профиль.",
    "1.3.1": "Мур-апдейт сделал авто-обновление обязательным и заботливым: Linux и Windows получают свежие версии "
                                  "сами.",
    "1.3.0": "Mesh принёс защищённое подключение, раздел безопасности, авто-обновление и проверку версий.",
    "1.2.0": "Windows-fix навёл порядок: подключение по внутреннему IP, авто-генерация профиля, локальный QR, "
                                  "авто-восстановление порта, настройки через переменные окружения и правила брандмауэра.",
    "1.1.0": "Свежая рыба улучшила умный фильтр ключей, добавила лимит в 120 ключей и честный исходящий IP."
}

# Заголовок вкладки «Версии» — в стиле маскота (общий для всех языков).
VERSION_CHRONICLE = {
    "title": "🐾 Хроники "
             "кота-маскота Aurora",
    "sub": "Каждый релиз — "
           "новая глава: "
           "кот взрослеет, "
           "учится, охраняет "
           "и приносит подарки.",
}


_BOOT_TS = time.time()   # время старта процесса (для /api/settings.uptime)

# --- периметр plaintext-файлов Xray/keytest (A-072) ---
# Формат xray.json/keytest-конфигов менять нельзя (требование xray), поэтому
# секреты в них защищаются правами доступа: POSIX 0600 (файл) / 0700 (каталог),
# Windows DACL — владелец + SYSTEM + Administrators, наследование отключено.
PLAINTEXT_FILE_MODE = 0o600
PLAINTEXT_DIR_MODE = 0o700

# --- авто-обновление (GitHub Releases) ---
# Обязательное: публичная сборка всегда обновляется с этого репо.
# Локальное отключение/обход НЕ предусмотрен (управляется только политикой релизов).
UPDATE_REPO = "efremov-aa/aurora-proxy"
# Пиннированный Ed25519-ключ подписи релизов (fail-closed: без ключа обновление не ставится)
UPDATE_PUBKEY = "6159031f0fd9ab6c5074f9bef99f5ac125df75e05bdeaa772860236fb85e3371"
UPDATE_CHECK_INTERVAL = 15 * 60  # проверка признаков обновления каждые 15 минут

# --- пути (относительно корня проекта) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("AURORA_DATA_DIR", os.path.join(BASE_DIR, "data"))
XRAY_CONFIG = os.path.join(BASE_DIR, "xray.json")
LOG_FILE = os.path.join(BASE_DIR, "aurora.log")

os.makedirs(DATA_DIR, exist_ok=True)

AUTO_REFRESH_INTERVAL = 1800   # фоновый цикл обновления github-ключей (сек)

# --- порты (привязаны к клиентским устройствам, НЕ менять без запроса) ---
UI_PORT = int(os.environ.get("AURORA_UI_PORT", "8890"))  # панель Aurora
XRAY_PORT = int(os.environ.get("AURORA_XRAY_PORT", "8899"))  # mixed-вход xray (http+socks)
XRAY_API_PORT = int(os.environ.get("AURORA_XRAY_API_PORT", "8897"))  # докодемо-API xray (статистика)
TGWS_PORT = int(os.environ.get("AURORA_TGWS_PORT", "443"))  # Telegram WS-прокси (443; 1443 блокировался РКН снаружи)
# Браузерное расширение (MV3/DNR): хост прокси, режим RU-байпаса, версия правил.
RU_BYPASS = os.environ.get("AURORA_RU_BYPASS", "1").strip().lower() not in (
    "0", "false", "no", "off", "нет", "выкл")
RULES_VERSION = (os.environ.get("AURORA_RULES_VERSION", "1").strip() or "1")[:32]
EXT_HOST = os.environ.get("AURORA_EXT_HOST", "").strip()


# --- A-161: архивы браузерного расширения (PRO-фича) ---
# Лежат в assets/ рядом с кодом; раздаёт их панель. Имя файла - только из
# белого списка ниже, путь из запроса никогда не подставляется.
EXT_ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
EXT_PACKAGES = {}  # A-164: пакеты расширения раздаёт только головной
# сервер; в клиентской сборке их нет, /api/ext/license вернёт packages=[]




def ext_proxy_host():
    """Адрес прокси для расширения: AURORA_EXT_HOST -> VM_HOST -> 127.0.0.1."""
    for cand in (EXT_HOST, VM_HOST, ""):
        if cand and cand not in ("0.0.0.0", "::", "*"):
            return cand
    return "127.0.0.1"

# --- сеть (значения из env, дефолты безопасны/пустые) ---
VM_HOST = os.environ.get("AURORA_HOST", "127.0.0.1")    # адрес сервера для внешних ссылок/QR
WHITE_IP = os.environ.get("AURORA_WHITE_IP", "")        # белый IP провайдера — фильтр «не выход VPN»
_DIRECT_IP_LOCK = threading.Lock()
_DIRECT_IP_CACHE = {"ip": "", "ts": 0.0}
_DIRECT_IP_TTL_S = 300
_DIRECT_IP_INFLIGHT = False   # A-280: single-flight, сеть выполняется вне _DIRECT_IP_LOCK


def get_direct_ip(force=False):
    """Прямой IP сервера (без VPN). A-280: сетевой запрос - ВНЕ лока."""
    global _DIRECT_IP_INFLIGHT
    configured = str(WHITE_IP or "").strip()
    if configured:
        try:
            return str(ipaddress.ip_address(configured))
        except ValueError:
            return ""
    now = time.time()
    with _DIRECT_IP_LOCK:
        if not force and _DIRECT_IP_CACHE["ip"] and now - _DIRECT_IP_CACHE["ts"] < _DIRECT_IP_TTL_S:
            return _DIRECT_IP_CACHE["ip"]
        if _DIRECT_IP_INFLIGHT:
            return _DIRECT_IP_CACHE["ip"]
        _DIRECT_IP_INFLIGHT = True
    value = ""
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://api.ipify.org?format=json", timeout=5) as response:
            value = json.loads(response.read().decode("utf-8")).get("ip", "")
        value = str(ipaddress.ip_address(str(value)))
    except Exception:
        value = ""
    finally:
        with _DIRECT_IP_LOCK:
            if value:
                _DIRECT_IP_CACHE["ip"] = value
                _DIRECT_IP_CACHE["ts"] = time.time()
            _DIRECT_IP_INFLIGHT = False
    return value

# --- источники github-ключей ---
# Репо barry-far/V2ray-Config: файлы регенерируются workflow main.yml каждые 15 минут.
GITHUB_SOURCES = ["https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt"]

# --- ру-байпас: RU-домены уходят на direct (без VPN) ---
# Базовый список (актуально навсегда: обновления ПО, ключевые RU-сервисы).
# При недоступности github-источников используется ТОЛЬКО он.
RU_DOMAINS_STATIC = [
    "github.com", "githubusercontent.com", "raw.githubusercontent.com",
    "github.io", "huggingface.co", "hf-mirror.com",
    "pypi.org", "files.pythonhosted.org", "npmjs.org",
    "registry.npmjs.org", "crates.io", "static.crates.io",
    "nuget.org", "download.visualstudio.microsoft.com", "dotnet.microsoft.com",
    "pypi.python.org", "files.pythonhosted.org",
    "jetbrains.com", "download.jetbrains.com", "plugins.jetbrains.com",
    "opencode.ai",
    "yandex.ru", "ya.ru", "vk.com", "ok.ru", "mail.ru", "vk.ru",
    "rutube.ru", "gosuslugi.ru", "mos.ru", "kremlin.ru", "gov.ru",
]

# Списки с github для расширения базового набора (плейн-домены ИЛИ domain:...).
RU_DOMAINS_SOURCES = [
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt",
    "https://raw.githubusercontent.com/UnRKN/ru-blocklist/refs/heads/main/ru-blocklist-domain.txt",
]

# Кэш загруженного списка (TTL 900с; при сбое = пустой, работает фолбэк).
RU_DOMAINS_TTL_S = 900
MAX_RU_SOURCE_BYTES = 4 * 1024 * 1024
MAX_RU_SOURCE_LINES = 200000
RU_DOMAINS_LOCK = threading.Lock()
RU_DOMAINS_CACHE = {"list": [], "ts": 0.0}

# --- лимиты ---
MAX_USER_KEYS = 120       # максимум ключей в пуле (60 -> 120: большая выборка из 2529 reality-ключей)
MAX_PING_MS = 700        # выше = ключ мёртв (правило юзера: >700мс мёртвый)
EGRESS_TTL_S = 60         # кэш egress
ROTATE_COOLDOWN_S = 180.0 # демпф ротации
VPN_KEYS_N = 4            # сколько ключей попадает в xray.json при VPN ON

# --- внешнее подключение (VLESS-Reality inbound :8443) ---
# Отключено по умолчанию. Заполните свои ВСЕ поля через env AURORA_VLESS_* (см. README/.env.example),
# иначе register_public_inbound() вернёт False и внешний inbound не создастся.
def _parse_port(value):
    if type(value) is int:
        return value if 1 <= value <= 65535 else None
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value.isdigit():
        return None
    value = int(value)
    return value if 1 <= value <= 65535 else None


def canonical_uuid(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = uuid.UUID(value.strip())
    except (ValueError, AttributeError):
        return None
    if parsed.int == 0:
        return None
    return str(parsed)


def _valid_x25519(value):
    if not isinstance(value, str) or len(value) != 43:
        return False
    if any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value):
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error):
        return False
    if len(raw) != 32:
        return False
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value


def _valid_short_id(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return ""
    if len(value) > 16 or len(value) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        return None
    return value.lower()


def _valid_sni(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or any(ch in value for ch in "/?#@,; \t\r\n"):
        return None
    try:
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not value or len(value) > 253 or "*" in value:
        return None
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value):
        return None
    return value


METADATA_HOSTS = frozenset((
    "169.254.169.254", "100.100.100.200", "168.63.129.16", "fd00:ec2::254",
))


def _read_setup_token():
    value = os.environ.get("AURORA_SETUP_TOKEN", "").strip()
    if len(value) < 16 or len(value) > 256:
        return ""
    if any(ch.isspace() or ord(ch) < 33 or ord(ch) > 126 for ch in value):
        return ""
    return value


SETUP_TOKEN = _read_setup_token()


def _private_links_allowed():
    return os.environ.get("AURORA_ALLOW_PRIVATE_LINK", "").lower() in ("1", "true", "yes", "on")


def _valid_public_host(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or any(ch in value for ch in "/?#@,; \t\r\n"):
        return None
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    elif "[" in value or "]" in value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            value = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value):
            return None
        if value == "localhost" or value.endswith(".local") or value.endswith(".internal"):
            return None
        return value
    if str(address) in METADATA_HOSTS:
        return None
    if not address.is_global:
        private_ok = _private_links_allowed() and address.is_private and not address.is_loopback and not address.is_link_local and not address.is_unspecified and not address.is_multicast
        if not private_ok:
            return None
    return str(address)


def external_link_host(raw=None):
    for name in ("AURORA_VLESS_HOST", "AURORA_HOST"):
        if name in os.environ:
            return _valid_public_host(os.environ.get(name, "")) or ""
    if raw is None:
        raw = VLESS_PUBLIC
    if isinstance(raw, dict):
        host = _valid_public_host(raw.get("host", ""))
        if host:
            return host
    get_public_ip = globals().get("get_public_ip")
    if callable(get_public_ip):
        return _valid_public_host(get_public_ip() or "") or ""
    return ""


def _format_link_host(host):
    if not host:
        return ""
    try:
        if ipaddress.ip_address(host).version == 6:
            return "[%s]" % host
    except ValueError:
        pass
    return host


def vless_public(raw=None):
    if raw is None:
        raw = VLESS_PUBLIC
    if not isinstance(raw, dict):
        return {"enabled": False, "configured": False}
    # A-118: выключатель внешнего VLESS из панели (env только задаёт настройки).
    toggle_on = _settings.get("vless_enabled", True) is True
    enabled = raw.get("enabled") is True and toggle_on
    port = _parse_port(raw.get("port", 8443))
    configured = bool(raw.get("enabled") is True and canonical_uuid(raw.get("uuid")))
    out = {
        "enabled": enabled,
        "configured": configured,
        "port": port if port is not None else 0,
        "host": external_link_host(raw),
        "uuid": canonical_uuid(raw.get("uuid")),
        "private_key": raw.get("private_key") if _valid_x25519(raw.get("private_key")) else "",
        "public_key": raw.get("public_key") if _valid_x25519(raw.get("public_key")) else "",
        "short_id": _valid_short_id(raw.get("short_id", "")),
        "sni": _valid_sni(raw.get("sni", "www.microsoft.com")),
        "flow": raw.get("flow") if raw.get("flow") == "xtls-rprx-vision" else None,
    }
    if not enabled or port is None or not out["uuid"] or not out["private_key"] or not out["public_key"] or out["short_id"] is None or not out["sni"] or not out["flow"]:
        out["enabled"] = False
    return out


VLESS_PUBLIC = {
    "enabled": os.environ.get("AURORA_VLESS_ENABLED", "").lower() == "true",
    "port": _parse_port(os.environ.get("AURORA_VLESS_PORT", "8443")) or 0,
    "host": os.environ.get("AURORA_VLESS_HOST", "127.0.0.1"),
    "uuid": os.environ.get("AURORA_VLESS_UUID", ""),
    "private_key": os.environ.get("AURORA_VLESS_PRIVATE_KEY", ""),
    "public_key": os.environ.get("AURORA_VLESS_PUBLIC_KEY", ""),
    "short_id": os.environ.get("AURORA_VLESS_SHORT_ID", ""),
    "sni": os.environ.get("AURORA_VLESS_SNI", "www.microsoft.com"),
    "flow": os.environ.get("AURORA_VLESS_FLOW", "xtls-rprx-vision"),
}

# --- агент ПК (recovery, команды) ---
AGENT_TOKEN = ""
AGENT_UPDATE_URL = ""
AGENT_UPDATE_VERSION = ""

# --- настройки (сохранение в data/settings.json) ---
_LOCK = threading.RLock()   # RLock: set() берёт лок, save_settings берёт вложенно
_SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

_SETTINGS_DEFAULTS = {
    "vpn_mode": True,        # True = VPN активен (final = лучший ключ), False = прямой
    "auto_recovery": True,   # авто-восстановление канала через агента
    "continue_text": "",     # текст при отправке continue
    "ui_token": "",          # X-Auth-токен панели (пусто = как раньше, секреты видны в LAN)
    "mesh_tunnel": True,       # A-WARP-M-7: включён по умолчанию — клиенты подключаются к мастеру
    # A-WARP-PUB: rezervnyy kanal WARP (off/auto/on).
    # off - ne ispolzuetsya, auto - tolko pri pustom pule kljuchey.
    "warp_mode": "off",
    # A-118: внешний резервный канал (MASQUE/mihomo) и TG-WS-прокси.
    # Включаются/выключаются из панели; выключенный канал не поднимается.
    "masque_enabled": True,
    "tgws_enabled": True,
    # A-118: внешний VLESS-Reality inbound :8443 (тоже выключатель из панели).
    "vless_enabled": True,

    "game_tun": False,         # A-816: TUN-подсеть игровых узлов (требует root/CAP_NET_ADMIN)
    # A-827 (Ш4): три сценария на старте. Пусто = ещё не выбран.
    #   friends — играть с друзьями (свой игровой сервер можно)
    #   proxy   — свой прокси (игровой адаптер не поднимается)
    #   guest   — подключили к чужой Aurora (гость чужой группы)
    "game_scenario": "",
    # --- v1.4.0: сервер / меш / безопасность ---
    "server_name": "Home",       # имя сервера (хаб меша)
    "auto_refresh": True,        # автообновление github-ключей фоновым циклом
    "lan_only": False,           # панель: loopback + LAN (дефолт выключен для публичного деплоя)
    "block_scanners": False,     # 403 на шаблонные пути сканеров/ботов
    "rate_limit": True,          # демпфер 600 req/min на не-loopback IP
    "mesh_id": "mesh-aurora-home",  # идентификатор меша (invite-ссылка)
    "mesh_token": "",            # токен invite (генерируется при первом запросе)
    "twofa": False,              # требовать X-2FA на POST /api/*
    "ui_pin": "",                # пин 2FA (заголовок X-2FA)
    "show_mesh": True,           # вкладка «Меш-сеть» доступна локально
    # --- v1.7.0: политика сервиса + сегменты ---
    "setup_complete": False,   # мастер первичной настройки завершён
    "segment_title": "",         # своё название сегмента монитора (пусто = авто)
    "segment_regions": [],       # выбранные регионы (ru/global/eu/asia)
    "segment_custom": "",        # пользовательские домены (по одному на строку)
    # --- v1.8.0: гологоловной сервер (master) / авто-джойн / замок тестового сервера ---
    "mesh_own_secret": "",       # секрет собственного mesh-узла
    # A-1040 «Кот-смотритель»: автопроверка пула ключей по расписанию.
    # 0 минут = выключено (тогда keycheck_enabled тоже не важен).
    "keycheck_enabled": False,
    "keycheck_interval_min": 60,
    # A-120 «Кот-диспетчер»: авто-переключение резерва канала.
    "failover_enabled": False,
    "failover_interval_s": 60,
    # A-121: TG-уведомления владельцу (бот, не TG-WS-прокси).
    "notify_enabled": False,
    "notify_tg_token": "",
    "notify_tg_chat": "",
    # A-123: плановый бэкап по расписанию.
    "backup_schedule_enabled": False,
    "backup_interval_h": 24,
    "backup_keep": 7,
    "backup_password": "",
    "ui_port": UI_PORT,
    "xray_port": XRAY_PORT,
    "xray_api_port": XRAY_API_PORT,
    "tgws_port": TGWS_PORT,
}

_settings = dict(_SETTINGS_DEFAULTS)

# --- разделяемые runtime-состояния (фоновые треды пишут, web читает) ---
STATE = {
    "conns": 0,
    "devices": {},          # {ip: {name, conns, upload, download}}
    "up": 0,
    "down": 0,
    "tgws": {"running": False, "port_open": False, "secret_ok": False},
    "comm": {"state": "idle", "msg": ""},
    "vless_now": "-",
    "egress_ip": "-",
    "final_mode": "direct",
    "rusegment": {"running": False, "results": [], "ts": 0},
}
STATE_LOCK = threading.Lock()


class StorageDataError(ValueError):
    pass


def quarantine_file(path):
    source = os.path.abspath(path)
    if not os.path.isfile(source):
        return False
    index = 0
    while True:
        candidate = source + ".corrupt" if index == 0 else "%s.corrupt.%d" % (source, index)
        try:
            with open(source, "rb") as src:
                data = src.read()
            with open(candidate, "xb") as dst:
                dst.write(data)
                dst.flush()
                os.fsync(dst.fileno())
            try:
                import crypt

                crypt.restrict_file(candidate)
            except OSError:
                pass
            return True
        except FileExistsError:
            index += 1
        except OSError:
            return False


LOG_LOCK = threading.Lock()
# A-281: ротация лога. Без неё aurora.log рос бесконечно, а /api/log читал
# весь файл каждые 10 с (вкладка «Системный лог» поллит 3с/10с).
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 2
LOG_TAIL_BLOCK = 8192


def _rotate_log_if_needed():
    """Переименовать текущий лог в .1/.2, если он перерос порог."""
    for i in range(LOG_BACKUPS, 0, -1):
        src = LOG_FILE if i == 1 else "%s.%d" % (LOG_FILE, i - 1)
        dst = "%s.%d" % (LOG_FILE, i)
        if not os.path.exists(src):
            continue
        try:
            os.replace(src, dst)
        except OSError:
            pass


def log(msg):
    """Единая запись в лог (время + сообщение), потокобезопасно."""
    ts = _ts()
    with LOG_LOCK:
        try:
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) >= LOG_MAX_BYTES:
                _rotate_log_if_needed()
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write("[%s] %s\n" % (ts, msg))
        except OSError:
            pass


def log_tail(n=40):
    """Последние n строк LOG_FILE (для /api/log). Возвращает список строк.

    A-281: читаем только хвост файла блоками, а не f.read() целиком.
    """
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            try:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - LOG_TAIL_BLOCK), os.SEEK_SET)
                if size > LOG_TAIL_BLOCK:
                    f.readline()  # отбросить первую (обрезанную) строку
            except OSError:
                f.seek(0)
            return list(deque(f, maxlen=max(1, int(n))))
    except (OSError, ValueError, TypeError):
        return []


# --- RU-байпас: загрузка списка доменов (фолбэк на статический) ---
def _normalize_ru_line(line):
    """Из сырой строки github-списка -> домен без префикса domain: (или None)."""
    line = line.strip().lower()
    if not line or line.startswith(("#", "!", "//")):
        return None
    if line.startswith("domain:"):
        d = line[len("domain:"):].strip()
        return d or None
    if line.startswith("*.") or line.startswith("."):
        d = line.lstrip("*.")
        return d or None
    if " " in line or "/" in line:
        return None
    return line


def _fetch_ru_sources():
    """Скачивает RU_DOMAINS_SOURCES с github, возвращает список доменов."""
    import urllib.request
    domains = []
    seen = {}
    for url in RU_DOMAINS_SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Aurora/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                raw_length = r.headers.get("Content-Length")
                if raw_length is not None:
                    if not str(raw_length).isdigit():
                        raise ValueError("invalid content length")
                    if int(raw_length) > MAX_RU_SOURCE_BYTES:
                        raise ValueError("ru source too large")
                data = r.read(MAX_RU_SOURCE_BYTES + 1)
                if len(data) > MAX_RU_SOURCE_BYTES:
                    raise ValueError("ru source too large")
                body = data.decode("utf-8")
                if len(body.splitlines()) > MAX_RU_SOURCE_LINES:
                    raise ValueError("too many ru source lines")
            for ln in body.splitlines():
                d = _normalize_ru_line(ln)
                if d and d not in seen:
                    seen[d] = 1
                    domains.append(d)
        except Exception as e:
            log("ru-bypass: источник %s недоступен: %s" % (url, e))
    return domains


def ru_domains():
    """Актуальный список RU-доменов для байпаса (кэш TTL + фолбэк на статику)."""
    now = time.time()
    with RU_DOMAINS_LOCK:
        cached = RU_DOMAINS_CACHE["list"]
        if cached and now - RU_DOMAINS_CACHE["ts"] < RU_DOMAINS_TTL_S:
            return cached
    fetched = _fetch_ru_sources()
    with RU_DOMAINS_LOCK:
        # фолбэк: при пустой загрузке — статический минимум
        merged = fetched if fetched else list(RU_DOMAINS_STATIC)
        # дедуп цельном (static мог прийти первым)
        seen = {}
        final = []
        for d in merged + RU_DOMAINS_STATIC:
            if d and d not in seen:
                seen[d] = 1
                final.append(d)
        RU_DOMAINS_CACHE["list"] = final
        RU_DOMAINS_CACHE["ts"] = now
        log("ru-bypass: доменов %d (%s)" % (
            len(final), "github" if fetched else "static fallback"))
    return RU_DOMAINS_CACHE["list"]


# --- сегменты монитора (t-rusegment): регионы + свои домены ---
REGIONS = {
    "ru": {"title": "Ру-сегмент", "flag": "🇷🇺", "domains": [
        "yandex.ru", "ya.ru", "vk.com", "ok.ru", "mail.ru", "rambler.ru",
        "lenta.ru", "rbc.ru", "gazeta.ru", "kommersant.ru", "rg.ru",
        "kremlin.ru", "gosuslugi.ru", "gov.ru", "sberbank.ru", "tinkoff.ru",
        "avito.ru", "ozon.ru", "wildberries.ru", "kinopoisk.ru", "rutube.ru",
        "matchtv.ru", "kp.ru", "mos.ru",
    ]},
    "global": {"title": "Международный сегмент", "flag": "🌐", "domains": [
        "google.com", "youtube.com", "wikipedia.org", "github.com",
        "cloudflare.com", "mozilla.org", "openai.com", "netflix.com",
        "amazon.com", "reddit.com", "x.com", "instagram.com",
        "microsoft.com", "apple.com", "stackoverflow.com", "medium.com",
    ]},
    "eu": {"title": "ЕС-сегмент", "flag": "🇪🇺", "domains": [
        "bbc.com", "dw.com", "lemonde.fr", "elpais.com", "ilpost.it",
        "france24.com", "rtve.es", "europarl.europa.eu", "rtl.be", "oe24.at",
    ]},
    "asia": {"title": "Азия", "flag": "🌏", "domains": [
        "baidu.com", "alibaba.com", "taobao.com", "tmall.com",
        "naver.com", "yahoo.co.jp", "rakuten.co.jp", "kakaku.com",
        "sina.com.cn", "line.me",
    ]},
}


def _seg_line_to_domain(line):
    """Нормализация строки списка доменов (переиспользует _normalize_ru_line)."""
    d = _normalize_ru_line(line)
    if not d or "." not in d:
        return None
    return d


def segment_regions():
    """Выбранные регионы списком (только существующие в REGIONS)."""
    raw = get("segment_regions") or ["ru"]
    if isinstance(raw, str):
        raw = [raw]
    out = []
    for r in raw:
        if r in REGIONS and r not in out:
            out.append(r)
    return out or ["ru"]


def segment_title():
    """Название вкладки монитора: своё или авто (один регион — его имя, иначе флаги)."""
    own = (get("segment_title") or "").strip()
    if own:
        return own
    sel = segment_regions()
    if len(sel) == 1 and REGIONS.get(sel[0], {}).get("title"):
        return REGIONS[sel[0]]["title"]
    flags = [REGIONS[r]["flag"] for r in sel]
    return "Сегмент" if not flags else " ".join(flags) + " сегмент"


def segment_flag():
    """Флаг/эмодзи вкладки монитора (регионы, иначе глобус)."""
    sel = segment_regions()
    if len(sel) == 1:
        return REGIONS[sel[0]].get("flag", "🌐")
    return "🌐"


# --- v1.8.0: рандомное уникальное имя сервера ---
_NAME_ADJ = ["Мур", "Барс", "Снеж", "Рыж", "Полос", "Тих", "Быстр", "Хит", "Добр", "Гром"]
_NAME_NOUN = ["кот", "барсик", "мурзик", "лео", "тишка", "снежок", "рыжик", "марс", "симба", "том"]


def random_server_name(taken=None, tries=20):
    """Случайное имя сервера, не пересекающееся с уже существующими (taken)."""
    import secrets
    seen = {str(x or "").strip().lower() for x in (taken or [])}
    for _ in range(tries):
        name = "%s-%s-%s" % (
            _NAME_ADJ[secrets.randbelow(len(_NAME_ADJ))],
            _NAME_NOUN[secrets.randbelow(len(_NAME_NOUN))],
            secrets.token_hex(2),
        )
        if name.lower() not in seen:
            return name
    return "Aurora-%s" % secrets.token_hex(3)


def segment_domains():
    """Домены монитора: выбранные регионы + пользовательские домены (custom)."""
    domains = []
    for r in segment_regions():
        for d in REGIONS[r]["domains"]:
            if d not in domains:
                domains.append(d)
    custom = (get("segment_custom") or "").strip()
    if custom:
        for ln in custom.splitlines():
            d = _seg_line_to_domain(ln)
            if d and d not in domains:
                domains.append(d)
    return domains


def _ts():
    import datetime
    return datetime.datetime.now().strftime("%H:%M:%S")


def _is_nonnegative_int(value):
    return type(value) is int and value >= 0


def _validate_ports(data):
    ports = {}
    for key in ("ui_port", "xray_port", "xray_api_port", "tgws_port"):
        value = data.get(key, _SETTINGS_DEFAULTS[key])
        if type(value) is not int or value < 1 or value > 65535:
            return None
        ports[key] = value
    values = list(ports.values())
    if any(values.count(value) > 1 for value in values):
        return None
    return ports


def _validate_settings(raw):
    if not isinstance(raw, dict):
        raise ValueError("root is not an object")
    bool_keys = (
        "vpn_mode", "auto_recovery", "auto_refresh", "lan_only",
        "block_scanners", "rate_limit", "twofa", "show_mesh", "setup_complete",
        "masque_enabled", "tgws_enabled", "vless_enabled", "keycheck_enabled",
        "failover_enabled", "notify_enabled", "backup_schedule_enabled",
    )
    string_keys = (
        "continue_text", "ui_token", "server_name", "mesh_id", "mesh_token",
        "ui_pin", "segment_title", "segment_custom", "mesh_own_secret",
        "notify_tg_token", "notify_tg_chat", "backup_password",
    )
    list_keys = ("segment_regions",)
    for key in bool_keys:
        if key in raw and type(raw[key]) is not bool:
            raise ValueError("%s is not a boolean" % key)
    for key in string_keys:
        if key in raw and not isinstance(raw[key], str):
            raise ValueError("%s is not a string" % key)
    for key in list_keys:
        if key in raw and (not isinstance(raw[key], list)
                           or any(not isinstance(x, str) for x in raw[key])):
            raise ValueError("%s is not a string list" % key)
    # A-1040: интервал автопроверки. 0 = выключено, максимум неделя.
    if "keycheck_interval_min" in raw:
        value = raw["keycheck_interval_min"]
        if (type(value) is not int or value < 0 or value > 10080):
            raise ValueError("keycheck_interval_min is out of range")
    # A-120/A-123: интервалы диспетчера и планового бэкапа.
    if "failover_interval_s" in raw:
        value = raw["failover_interval_s"]
        if (type(value) is not int or value < 30 or value > 3600):
            raise ValueError("failover_interval_s is out of range")
    if "backup_interval_h" in raw:
        value = raw["backup_interval_h"]
        if (type(value) is not int or value < 1 or value > 168):
            raise ValueError("backup_interval_h is out of range")
    if "backup_keep" in raw:
        value = raw["backup_keep"]
        if (type(value) is not int or value < 1 or value > 60):
            raise ValueError("backup_keep is out of range")
    if raw.get("ui_pin") and not re.fullmatch(r"[0-9]{6}", raw["ui_pin"]):
        raise ValueError("ui_pin must be six ASCII digits")
    if raw.get("ui_token") and not 12 <= len(raw["ui_token"]) <= 256:
        raise ValueError("ui_token length is invalid")
    merged = dict(_SETTINGS_DEFAULTS)
    merged.update({k: raw[k] for k in raw if k in _SETTINGS_DEFAULTS})
    if _validate_ports(merged) is None:
        raise ValueError("ports are invalid")
    return merged


def _storage_failure(path, reason):
    quarantine_file(path)
    raise StorageDataError("%s: %s" % (os.path.basename(path), reason))


def _apply_port_overrides(settings):
    global UI_PORT, XRAY_PORT, XRAY_API_PORT, TGWS_PORT
    ports = _validate_ports(settings)
    if ports is None:
        return False
    UI_PORT = ports["ui_port"]
    XRAY_PORT = ports["xray_port"]
    XRAY_API_PORT = ports["xray_api_port"]
    TGWS_PORT = ports["tgws_port"]
    return True


# --- настройки ---
def _apply_mesh_env():
    """A-275: env-флаг релея применяется ПОСЛЕ загрузки settings, а не на импорте.

    Раньше set("mesh_tunnel", True) вызывался на уровне модуля, когда _settings ещё
    был равен _SETTINGS_DEFAULTS: на диск попадали дефолты вместо содержимого файла
    (терялись ui_token, ui_pin, server_name). Теперь трогаем только этот один ключ
    и только в памяти - источник истины по-прежнему env.
    """
    if not MESH_TUNNEL_ENV or _settings.get("mesh_tunnel"):
        return
    _settings["mesh_tunnel"] = True
    log("mesh: релей-туннель включён через AURORA_MESH_TUNNEL")


def _apply_game_env():
    """A-816: env-флаг игрового TUN, тот же приём, что и для релея (A-275).

    Только в памяти и только один ключ. На диск не пишем: источник истины - env,
    иначе игнорирование env в юните навсегда записало бы дефолт.
    """
    if not GAME_TUN_ENV or _settings.get("game_tun"):
        return
    _settings["game_tun"] = True
    log("mesh: игровой TUN включён через AURORA_MESH_GAME_TUN")


def load_settings():
    """Читает data/settings.json (выживают только известные ключи)."""
    global _settings
    with _LOCK:
        import crypt
        missing = object()
        try:
            raw = crypt.load_json(_SETTINGS_FILE, default=missing)
        except crypt.StorageError as e:
            _storage_failure(_SETTINGS_FILE, str(e))
        if raw is missing:
            _settings = dict(_SETTINGS_DEFAULTS)
            if not _apply_port_overrides(_settings):
                raise ValueError("ports are invalid")
            _apply_mesh_env()
            _apply_game_env()
            return
        try:
            merged = _validate_settings(raw)
        except (TypeError, ValueError) as e:
            _storage_failure(_SETTINGS_FILE, str(e))
        try:
            crypt.save_json(_SETTINGS_FILE, merged)
        except (crypt.StorageError, OSError) as e:
            _storage_failure(_SETTINGS_FILE, str(e))
        if not _apply_port_overrides(merged):
            _storage_failure(_SETTINGS_FILE, "ports are invalid")
            return
        _settings = merged
        _apply_mesh_env()
        _apply_game_env()


def _persist_settings(value):
    import crypt
    crypt.save_json(_SETTINGS_FILE, value)


def save_settings():
    """Атомарно пишет настройки в data/settings.json."""
    import crypt
    with _LOCK:
        try:
            _persist_settings(_settings)
        except (crypt.StorageError, OSError) as e:
            log("settings: не удалось сохранить: %s" % e)
            return False
    return True


def reset_settings():
    """Сброс настроек к значениям по умолчанию (кнопка «Сбросить всё»)."""
    import crypt
    with _LOCK:
        candidate = dict(_SETTINGS_DEFAULTS)
        try:
            _persist_settings(candidate)
        except (crypt.StorageError, OSError) as e:
            log("settings: не удалось сохранить: %s" % e)
            return False
        _settings.clear()
        _settings.update(candidate)
    log("settings: сброшены к значениям по умолчанию")
    return True




def get(key, default=None):
    return _settings.get(key, default)


def set_many(values, strict=True):
    import crypt
    if not isinstance(values, dict):
        return False
    with _LOCK:
        candidate = dict(_settings)
        candidate.update(values)
        if strict:
            try:
                candidate = _validate_settings(candidate)
            except (TypeError, ValueError) as e:
                log("settings: невалидное значение: %s" % e)
                return False
        try:
            _persist_settings(candidate)
        except (crypt.StorageError, OSError) as e:
            log("settings: не удалось сохранить: %s" % e)
            return False
        _settings.clear()
        _settings.update(candidate)
    return True


def set(key, value):
    return set_many({key: value}, strict=key in _SETTINGS_DEFAULTS)


def update_state_sub(key, **kw):
    """Атомарный апдейт вложенного словаря STATE (напр. tgws) под локом."""
    with STATE_LOCK:
        STATE.setdefault(key, {}).update(kw)


def update_state(**kw):
    """Безопасное обновление /api/state-словаря."""
    with STATE_LOCK:
        STATE.update(kw)


def get_state():
    with STATE_LOCK:
        return dict(STATE)


def state_fields():
    """Плоская копия STATE для JSON-ответа."""
    return get_state()



# --- A-151: релей-туннель между узлами меш (роль/адреса - из env) ---
# По умолчанию выключен: включается только приказом владельца.
# Секрет сети (AURORA_MESH_SECRET) в лог/конфиг/панель не попадает.
def _read_mesh_flag(name):
    v = (os.environ.get(name, "") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


MESH_TUNNEL_ENV = _read_mesh_flag("AURORA_MESH_TUNNEL")
GAME_TUN_ENV = _read_mesh_flag("AURORA_MESH_GAME_TUN")
MESH_SECRET = (os.environ.get("AURORA_MESH_SECRET", "") or "").strip()
MESH_PUBLIC_ADDR = (os.environ.get("AURORA_MESH_PUBLIC_ADDR", "") or "").strip()
# A-275: флаг НЕ применяется на уровне модуля (стирал бы settings целиком).
# Его применяет load_settings() -> _apply_mesh_env(), уже после чтения файла.

