# Сборка и деплой Aurora на GitHub (инструкция для всех)

## 1. Структура релиза

```
Aurora-v1.X.Y-linux.zip          # Linux-сборка (код + ui + proxy)
Aurora-v1.X.Y-windows.zip        # Windows-сборка (код + ui + proxy)
Aurora-Setup-1.X.Y.exe         # Windows-установщик (PyInstaller + Inno Setup)
Aurora-v1.X.Y-linux.zip.sig      # Подпись Ed25519 (88 B)
Aurora-v1.X.Y-windows.zip.sig    # Подпись Ed25519 (88 B)
Aurora-Setup-1.X.Y.exe.sig     # Подпись Ed25519 (88 B)
```

Все ассеты подписываются **одним и тем же seed'ом** (файл `aurora_release_signing.key`,
`%USERPROFILE%\.config\opencode\`). Подпись проверяется ключом, вшитым в `config.py`
(`UPDATE_PUBKEY`). **Важно:** seed на диске и вшитый в сборки ключ должны совпадать,
иначе автообновление отвергнет релиз.

## 2. Сборка архивов

```bash
cd aurora_public
# linux.zip
zip -r ../Aurora-v1.X.Y-linux.zip *.py proxy/ ui/ *.service run_tgws.sh Dockerfile docker-compose.yml .env.example README.md EXTENSION.md
# windows.zip
zip -r ../Aurora-v1.X.Y-windows.zip windows/*.py windows/proxy/ windows/ui/
```

## 3. Сборка установщика Windows

Требования: Python 3.12+, PyInstaller 6.x, Inno Setup 7.

```bash
cd windows
# 1) PyInstaller (onedir, console=False)
pyinstaller --clean --noconfirm --distpath %TEMP%\win_build\dist --workpath %TEMP%\win_build\build Aurora.spec
# 2) Inno Setup
"C:\Program Files\Inno Setup 7\ISCC.exe" /DSrcDir=%TEMP%\win_build\dist\Aurora installer\install.iss
# Результат: installer\output\Aurora-Setup-1.X.Y.exe
```

**Важно:** путь к `install.iss` не должен содержать пробелов (ISCC разбивает аргумент).
Копируйте `install.iss` во временную папку без пробелов перед запуском.

## 4. Подпись ассетов

```python
import release_sign as rs
SEED = open(r"%USERPROFILE%\.config\opencode\aurora_release_signing.key", "rb").read().strip()
if len(SEED) == 64: SEED = base64.b64decode(SEED)[:32]
sig = rs.sign_release(SEED, "efremov-aa/aurora-proxy", "1.X.Y", asset_name, data)
# Сохранить в asset_name.sig (ASCII, 88 B)
```

**Проверка (обязательная, двумя ключами):**
1. `rs.verify_release(data, sig, rs.public_key(SEED), ...)` — подпись самого seed'а
2. `rs.verify_release(data, sig, rs.parse_pubkey(config.UPDATE_PUBKEY), ...)` — ключ из сборок

Обе должны быть OK. Если вторая FAIL — seed на диске не тот, релиз не загружать.

## 5. Деплой на GitHub

```bash
cd aurora_public
git add <изменённые файлы>
git commit -m "v1.X.Y: описание"
git push https://<login>:<PAT>@github.com/efremov-aa/aurora-proxy.git Aurora
git push https://<login>:<PAT>@github.com/efremov-aa/aurora-proxy.git Aurora:nightly
git tag -a v1.X.Y -m "v1.X.Y"
git push https://<login>:<PAT>@github.com/efremov-aa/aurora-proxy.git v1.X.Y
```

Ассеты загружать через GitHub API (PAT):
```python
# Создать релиз
POST /repos/efremov-aa/aurora-proxy/releases
{"tag_name": "v1.X.Y", "name": "Aurora v1.X.Y «Название»", "body": "..."}

# Загрузить ассет
POST https://uploads.github.com/repos/efremov-aa/aurora-proxy/releases/{id}/assets?name=Aurora-v1.X.Y-linux.zip
Content-Type: application/octet-stream
```

**Важно:** загрузка ассетов через `api.github.com` даёт 404 — используйте `uploads.github.com`.

## 6. xray: скрытие и авто-удаление

В Windows-сборке xray запускается как подпроцесс (`XRAY_MANAGE=proc`) и должен быть **полностью скрытым**:
- `_xray_proc_start` передаёт `creationflags=config.HIDE_FLAG` (CREATE_NO_WINDOW) — консоль не появляется.
- `_xray_proc_stop` зарегистрирован через `atexit.register` — при завершении работы (в т.ч. некорректном) xray завершается.

**Проверка:** при работе Windows-сборки не должно быть окон консоли xray; после завершения Aurora процесс xray отсутствует.

## 7. Чек-лист перед загрузкой

- [ ] Тесты публичных сборок зелёные (53/53)
- [ ] `py_compile` всех изменённых файлов — OK
- [ ] `node --check ui/app.js` — OK
- [ ] Подпись проходит проверку обоими ключами
- [ ] Установщик собран и smoke-тест пройден (процесс жив, порт слушает)
- [ ] Версия в `config.py` обновлена (Linux + Windows)
- [ ] Тег указывает на правильный коммит (`git rev-parse v1.X.Y^{commit}`)
