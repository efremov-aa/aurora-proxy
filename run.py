# Aurora v1.0 — лаунчер: инициализация и запуск всех фоновых циклов.

import os
import signal
import threading

import config
import core
import mesh
import pool
import rusegment
import security
import subs
import telemetry
import tgws
import updater
from api import serve


def _boot():
    """Стартовая последовательность: настройки -> ключи -> sync -> фоновые треды."""
    config.load_settings()
    security.init()  # admin-токен + chmod data/ (до любых действий)
    # v1.8.0: уникальное имя сервера + авто-вступление в меш головного (фон)
    mesh.ensure_unique_name()
    threading.Thread(target=mesh.auto_join, daemon=True).start()
    pool.load()
    subs.load()  # подписки — до сборки конфига (клиенты vless-in)
    pool.cleanup()  # убрать мёртвые github-ключи при старте
    config.log("Aurora v%s boot" % config.VERSION)

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
