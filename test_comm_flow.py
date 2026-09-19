# Тест-драйв comm-флоу для док-бара: проверяем, что каждая операция
# корректно проходит фазы и ВОЗВРАЩАЕТСЯ в idle (ни один путь не залипает).
# Не трогает настоящий xray: только config.update_state + мок-таймеры.
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
import source

# --- фейковое окружение ---
config.GITHUB_SOURCES = []          # не качаем списки в тесте
config.DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
config.WHITE_IP = ""


def now():
    return config.get_state().get("comm", {})


# 1) refresh_from_github: loading (пул пустой -> _comm_done в конце)
print("== 1) refresh_from_github (пусто) ==")
n = source.refresh_from_github()
st = now()
print("after refresh: comm=%r" % st)
assert st["state"] == "done", "ожидали done, получили %s" % st
# дать таймеру _comm_done сработать (TTL сокращён только локально — здесь ждём реальный 10с)
time.sleep(11)
st = now()
print("после TTL: comm=%r" % st)
assert st["state"] == "idle", "не вернулись в idle: %s" % st

# 2) проверка что guard не затирает новую операцию: ставим running, поверх таймер done игнорим
print("== 2) guard: новая операция не затирается чужим таймером ==")
config.update_state(comm={"state": "running", "msg": "искусственный running"})
# эмулируем просроченный таймер от старой done
source._comm_done("старая done")
# немедленно: таймер ещё не стрельнул, синхронно проверить нельзя; вместо этого
# перезапустим простой сценарий: done -> потом СРАЗУ running (как check_all сразу после refresh)
config.update_state(comm={"state": "done", "msg": "x"})
config.update_state(comm={"state": "running", "msg": "check_all стартовал"})
time.sleep(11)
st = now()
print("после TTL при running: comm=%r" % st)
assert st["state"] == "running", "guard сломал running: %s" % st
config.update_state(comm={"state": "idle", "msg": ""})

# 3) check_all (синхронно, пустой пул): running -> done -> idle
print("== 3) check_all пустой пул ==")
r = source.check_all(bg=False)
print("check_all вернул: %r | comm=%r" % (r, now()))
assert now()["state"] == "done", "ожидали done"
time.sleep(11)
assert now()["state"] == "idle", "не вернулись в idle после check_all"
print("возврат в idle OK")

print("\nCOMM_FLOW_ALL_OK")