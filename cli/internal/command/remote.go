package command

// Запись секретного содержимого на удалённый хост по ssh: --file/--out
// принимают scp-подобный адрес "[user@]host:путь". Содержимое уходит через
// stdin ssh — без временного файла на локальном диске и без значений в argv
// (в argv только хост и путь, они не секретны). Хосты/алиасы — из ~/.ssh/config.

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// splitRemoteTarget разбирает scp-подобный адрес "[user@]host:путь".
// Не удалённое: нет ':', двоеточие в начале, однобуквенный префикс (диск
// Windows "C:\…") или слэш до двоеточия (локальный путь, содержащий ':' —
// его можно явно записать как "./имя:с:двоеточием", как в scp).
func splitRemoteTarget(s string) (host, path string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 1 || strings.ContainsAny(s[:i], `/\`) {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// shSingleQuote экранирует строку для POSIX-шелла одинарными кавычками.
func shSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sshWriteFile пишет data в файл на хосте через `ssh host 'cat > путь'`.
// Порядок повторяет локальный writeFile0600: создать под umask 077, затянуть
// права до усечения (фейл chmod оставляет старое содержимое целым), записать.
func sshWriteFile(host, path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("пустой путь в адресе %q — нужен [user@]host:/путь", host+":")
	}
	q := shSingleQuote(path)
	remote := fmt.Sprintf("umask 077 && { [ -e %s ] || : > %s; } && chmod 600 %s && cat > %s", q, q, q, q)
	cmd := exec.Command("ssh", "--", host, remote)
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("ssh %s: %s", host, msg)
		}
		return fmt.Errorf("ssh %s: %w", host, err)
	}
	return nil
}

// writeSecretFile — общая точка записи файла с секретами (export/render/
// get --out): scp-адрес уходит по ssh, остальное — локально с правами 0600.
func writeSecretFile(target string, data []byte) error {
	if host, rpath, ok := splitRemoteTarget(target); ok {
		return sshWriteFile(host, rpath, data)
	}
	return writeFile0600(target, data)
}
