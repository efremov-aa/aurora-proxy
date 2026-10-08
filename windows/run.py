# Aurora v1.0 — лаунчер: инициализация и запуск всех фоновых циклов.

import os
import threading

import config
import core
import extgate
import meshtunnel
import mesh
import pool
import recovery
import rusegment
import security
import subs
import telemetry
import tgws
import updater
from api import serve


def _start_game_tun():
    """A-816: TUN-подсеть игровых узлов, отдельный флаг game_tun.

    Вызывается ТОЛЬКО после успешного meshtunnel.start(): game_enabled() сам
    проверяет и туннель, и что узел не служебный, но порядок важен - без
    поднятого туннеля адаптер всё равно некуда слать пакеты.

    По умолчанию выключено: на Windows нужен WinTun, без него честный отказ в лог.
    """
    if not config.get("game_tun", False):
        return
    try:
        import meshtun
    except Exception as e:
        config.log("game-tun: модуль недоступен: %s" % type(e).__name__)
        return
    try:
        ok, why = meshtun.start()
    except Exception as e:
        config.log("game-tun: не запущен: %s: %s" % (type(e).__name__, e))
        return
    if ok:
        config.log("game-tun: TUN-подсеть игровых узлов запущена")
    else:
        config.log("game-tun: не запущена: %s" % why)


def _boot():
    """Стартовая последовательность: настройки -> ключи -> sync -> фоновые треды."""
    config.load_settings()
    security.init()  # admin-токен + chmod data/ (до любых действий)
    try:
        import crypt
        migrated = crypt.migrate_all()
        if migrated:
            config.log("boot: хранилище AURORA2 (%s)" % ", ".join(sorted(migrated)))
    except Exception as e:
        config.log("boot: миграция хранилища пропущена: %s" % e)
    config.ensure_vless()
    config.refresh_public_ip_async()
    config.open_firewall()
    # v1.8.0: уникальное имя сервера + авто-вступление в меш головного (фон)
    mesh.ensure_unique_name()
    threading.Thread(target=mesh.auto_join, daemon=True).start()
    pool.load()
    subs.load()  # подписки — до сборки конфига (клиенты vless-in)
    mesh.start_policy_loop()
    subs.start_background()
    extgate.start_background()  # A-111: лицензия PRO (прокси не падает при сети)
    # A-151: релей-туннель меш-сети. По умолчанию выключен (config.mesh_tunnel),
    # роль - из env AURORA_MESH_ROLE. Ошибки не роняют запуск: туннель - это канал,
    # а не условие жизни прокси.
    if config.get("mesh_tunnel", False):
        try:
            if meshtunnel.start(os.environ.get("AURORA_MESH_ROLE", "")):
                config.log("mesh: relay-туннель запущен")
                _start_game_tun()
        except Exception as e:
            config.log("mesh: relay-туннель не запущен: %s" % type(e).__name__)
    pool.cleanup()  # убрать мёртвые github-ключи при старте
    config.log("Aurora v%s boot" % config.VERSION)
    # A-272: A-102 просил наполнять ленту recovery реальными событиями,
    # но note() не вызывался нигде - лента вечно показывала "пусто".
    try:
        recovery.note("service started (boot)")
    except Exception as e:
        config.log("boot: %s" % e)

    # проверка/заполнение tgws-секрета и фоновый статус
    tgws.refresh_status()

    # фоновые циклы
    threading.Thread(target=telemetry.poll, daemon=True).start()
    threading.Thread(target=_startup_sync, daemon=True).start()
    core.start_watch()
    # обновление tgws-статуса каждые 30с
    def tgws_loop():
        import time
        while True:
            time.sleep(30)
            tgws.refresh_status()
    threading.Thread(target=tgws_loop, daemon=True).start()
    # обновление имён устройств
    threading.Thread(target=telemetry.resolve_names, daemon=True).start()
    # стартовая проверка ру-сегмента (фон, результаты — в /api/state)
    rusegment.start()
    # обязательное авто-обновление (без обхода; сервера на ручном — вне этой сборки)
    updater.auto_update()


def _startup_sync():
    """Стартовая синхронизация через 3с (даёт xray подняться и пулу загрузиться)."""
    import time
    import traceback
    import source
    time.sleep(3)
    try:
        core.sync()
    except Exception:
        config.log("boot: первый sync упал:\n%s" % traceback.format_exc())
    # при VPN ON: если кандидатов нет — чистка мёртвых, догрузка github, проверка ключей
    if config.get("vpn_mode", True):
        if not pool.get_keys():
            config.log("boot: пул пуст, загрузка github-ключей")
            try:
                n = source.refresh_from_github()
                config.log("boot: github-ключей добавлено: %d" % n)
            except Exception:
                config.log("boot: загрузка github-ключей упала:\n%s" % traceback.format_exc())
        # ключи ещё не проверены (статусы unchecked) — гоняем keytest в фоне;
        # final поднимет живой ключ через _final_watch после проверки.
        try:
            if pool.get_keys() and not pool.pick_final():
                config.log("boot: живых кандидатов нет, запускаю проверку ключей")
                source.check_all(bg=True)
        except Exception:
            config.log("boot: авто-проверка ключей упала:\n%s" % traceback.format_exc())


def main():
    _boot()
    serve()


if __name__ == "__main__":
    main()
