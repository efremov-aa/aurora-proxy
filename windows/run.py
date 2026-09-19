# Aurora v1.0 — лаунчер: инициализация и запуск всех фоновых циклов.

import signal
import threading
import time

import config
import core
import pool
import rusegment
import telemetry
import tgws
from api import serve


def _boot():
    """Стартовая последовательность: настройки -> ключи -> sync -> фоновые треды."""
    config.load_settings()
    pool.load()
    pool.cleanup()  # убрать мёртвые github-ключи при старте

    # внешний VLESS: автогенерация ключей (+inbound :8443) до сборки xray-конфига
    if hasattr(config, "ensure_vless"):
        config.ensure_vless()
    # Windows: разрешить наши порты в брандмауэре (best-effort)
    if hasattr(config, "open_firewall"):
        config.open_firewall()

    config.log("Aurora v%s boot" % config.VERSION)

    # проверка/заполнение tgws-секрета и фоновый статус
    tgws.refresh_status()
    # авто-старт tg-ws, если порт 1443 не открыт
    if not tgws.running():
        config.log("tgws: порт %d закрыт, авто-старт" % config.TGWS_PORT)
        tgws.restart()
        time.sleep(2)
        tgws.refresh_status()

    # фоновое определение публичного IP (для внешних ссылок/QR)
    if hasattr(config, "refresh_public_ip_async"):
        config.refresh_public_ip_async()

    # фоновые циклы
    threading.Thread(target=telemetry.poll, daemon=True).start()
    threading.Thread(target=_startup_sync, daemon=True).start()
    core.start_watch()

    # самолечение tgws: каждые 30с проверяем порт, при падении — рестарт
    def tgws_loop():
        while True:
            time.sleep(30)
            if not tgws.running():
                config.log("tgws: порт %d закрыт, авто-восстановление" % config.TGWS_PORT)
                tgws.restart()
                time.sleep(2)
            tgws.refresh_status()
    threading.Thread(target=tgws_loop, daemon=True).start()
    # обновление имён устройств
    threading.Thread(target=telemetry.resolve_names, daemon=True).start()
    # стартовая проверка ру-сегмента (фон, результаты — в /api/state)
    rusegment.start()


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