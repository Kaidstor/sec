package command

// Запись секретного содержимого на удалённый хост по ssh: --file/--out
// принимают scp-подобный адрес "[user@]host:путь". Содержимое уходит через
// stdin ssh — без временного файла на локальном диске и без значений в argv
// (в argv только хост и путь, они не секретны). Хосты/алиасы — из ~/.ssh/config.

import (
	"bytes"
	"fmt"
	"os"
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

// sshRun выполняет shell-команду на хосте: stdin уходит команде, stdout
// возвращается вызывающему. Секретное содержимое ходит только через stdin/stdout
// — в argv попадают лишь хост и заэкранированные пути, они не секретны.
// Второй результат — stderr команды (нужен, чтобы отличить «sudo просит пароль»
// от прочих ошибок).
func sshRun(host, remote string, stdin []byte) (stdout []byte, stderr string, err error) {
	cmd := exec.Command("ssh", "--", host, remote)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	stderr = strings.TrimSpace(errb.String())
	if err != nil {
		if stderr != "" {
			err = fmt.Errorf("ssh %s: %s", host, stderr)
		} else {
			err = fmt.Errorf("ssh %s: %w", host, err)
		}
	}
	return out.Bytes(), stderr, err
}

// sshStream выполняет команду на хосте, отдавая её вывод пользователю как есть
// (deploy --after: рестарт сервиса хочется видеть вживую, а не постфактум).
func sshStream(host, remote string) error {
	cmd := exec.Command("ssh", "--", host, remote)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh %s: %w", host, err)
	}
	return nil
}

// sudoWrap оборачивает shell-команду в неинтерактивный sudo. Пароль sec через
// себя не пропускает: если sudo его требует, вводить идут в sshSudoPrime.
func sudoWrap(remote string, sudo bool) string {
	if !sudo {
		return remote
	}
	return "sudo -n sh -c " + shSingleQuote(remote)
}

// sudoNeedsPassword — sudo отказал именно из-за пароля/TTY, а не из-за прав.
// Текст зависит от версии sudo и локали хоста, поэтому примет несколько.
func sudoNeedsPassword(stderr string) bool {
	s := strings.ToLower(stderr)
	for _, m := range []string{"password is required", "no tty present", "a terminal is required", "требуется пароль", "введите пароль"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// sshSudoPrime даёт ввести пароль sudo один раз в интерактивной ssh-сессии:
// `sudo -v` обновляет кэш credentials на хосте (обычно ~15 минут), после чего
// работает `sudo -n`. Пароль набирается на той стороне и через процесс sec не
// проходит вовсе.
func sshSudoPrime(host string) error {
	if stdinPiped() {
		return fmt.Errorf("sudo на %s требует пароль, а ввести его негде (stdin — не терминал);\n"+
			"     настрой NOPASSWD для нужной команды либо прогрей вручную: ssh -t %s sudo -v", host, host)
	}
	fmt.Fprintf(os.Stderr, "sec: sudo на %s требует пароль — вводи в ssh-сессии ниже (sec его не видит)\n", host)
	cmd := exec.Command("ssh", "-t", "--", host, "sudo -v")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("не удалось получить право sudo на %s: %w", host, err)
	}
	return nil
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
	_, _, err := sshRun(host, remote, data)
	return err
}

// writeSecretFile — общая точка записи файла с секретами (export/render/
// get --out): scp-адрес уходит по ssh, остальное — локально с правами 0600.
func writeSecretFile(target string, data []byte) error {
	if host, rpath, ok := splitRemoteTarget(target); ok {
		return sshWriteFile(host, rpath, data)
	}
	return writeFile0600(target, data)
}
