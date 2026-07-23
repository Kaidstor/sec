# Windows-поддержка — проверить вживую

Кросс-компиляция под `windows/amd64|arm64` проходит, тесты и `go vet` зелёные,
но поведение WinAPI проверяется только на реальной Windows-машине.

## Чек-лист

### Мастер-ключ (Credential Manager)
- [ ] Первый `sec set` создаёт ключ; запись видна в «Диспетчере учётных данных» (generic credential, target `sec/master`)
- [ ] Ключ переживает перезапуск/релогин и читается обратно (`sec info` → бэкенд keyring)
- [ ] `sec rekey` — ротация с перешифровкой стора
- [ ] Фолбэк на файл `%APPDATA%\sec\key`, если Credential Manager недоступен

### Скрытый ввод (`CONIN$` + SetConsoleMode)
- [ ] `sec set proj/KEY` в классической консоли, Windows Terminal и PowerShell — echo гасится и восстанавливается
- [ ] Ctrl-C во время ввода восстанавливает echo (exit 130)
- [ ] Git Bash / mintty: `CONIN$` может быть недоступен — должен выводиться совет про stdin/`--clipboard`, а не паника

### Буфер обмена (нативный Win32)
- [ ] `sec get proj/KEY --clip` / `sec set --clipboard` — значение доходит в обе стороны
- [ ] Кириллица/юникод в значении не бьются (CF_UNICODETEXT)
- [ ] Значение НЕ появляется в истории Win+V и НЕ уходит в облачный буфер (форматы ExcludeClipboardContentFromMonitorProcessing / CanIncludeInClipboardHistory=0 / CanUploadToCloudClipboard=0)
- [ ] `set --clipboard --clear` очищает буфер после сохранения

### Отложенная очистка буфера (`--clear-after`)
- [ ] Детач-воркер доживает после закрытия окна консоли (DETACHED_PROCESS)
- [ ] Буфер чистится только если значение не сменилось (скопированное позже — не трогается)

### `sec run` (execReplace вместо exec(2))
- [ ] Код выхода дочернего процесса пробрасывается наружу
- [ ] Ctrl-C прерывает ребёнка, сирот не остаётся
- [ ] Запуск `.bat`/`.cmd` — возможно, потребуется обёртка `cmd /c`

### Хранилище и пути
- [ ] Стор создаётся в `%LOCALAPPDATA%\sec\store.enc`, ключ-фолбэк — в `%APPDATA%\sec\key`
- [ ] `SEC_STORE` / `SEC_KEY_FILE` переопределяют пути
- [ ] Два параллельных `sec set` не дедлочат (LockFileEx) и не теряют запись
- [ ] `sec doctor` не даёт ложных ошибок (проверка Unix-прав пропущена → строка про NTFS ACL)

### Журнал
- [ ] `sec log` — колонка `by:` показывает реальное имя родителя (powershell, node, claude, …) через Toolhelp32

### Релиз
- [ ] goreleaser собирает zip `sec_<версия>_windows_{amd64,arm64}.zip` и заливает в GitHub Releases
- [ ] Homebrew-cask не сломался от появления windows-билдов
- [ ] `sec.exe` из архива запускается на чистой машине (SmartScreen/Defender — оценить, нужна ли подпись)

## Известные ограничения (осознанные)
- Скрытый ввод с консоли читает байты в кодировке консоли (не UTF-16) — не-ASCII значения надёжнее через `--clipboard`/stdin
- `sec completion` — только zsh/bash/fish; PowerShell-автодополнение не реализовано
- Права 0600/0700 на Windows не применяются — защита файлов на NTFS ACL профиля пользователя
