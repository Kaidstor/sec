package command

// envTarget — env-файл, с которым работают sec diff <proj> <цель> и sec deploy:
// локальный путь либо scp-адрес "[user@]host:/путь" (те же адреса, что у
// export --file / get --out). Здесь собраны все операции над этим файлом —
// чтение, запись, бэкап, команда после записи — чтобы удалённый и локальный
// случаи не расползлись по вызывающим командам.
//
// Значения секретов ходят только через stdin/stdout ssh: в argv попадают лишь
// хост и заэкранированный путь.

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type envTarget struct {
	host string // "" — файл на этой машине
	path string
}

// parseEnvTarget разбирает цель записи (--to): scp-адрес либо локальный путь.
func parseEnvTarget(s string) (envTarget, error) {
	if host, path, ok := splitRemoteTarget(s); ok {
		if path == "" {
			return envTarget{}, fmt.Errorf("пустой путь в адресе %q — нужен [user@]host:/путь", s)
		}
		return envTarget{host: host, path: path}, nil
	}
	if s == "" {
		return envTarget{}, errors.New("пустой путь к файлу")
	}
	return envTarget{path: s}, nil
}

// looksLikeEnvTarget — позиционный аргумент это env-файл, а не имя проекта
// (sec diff умеет и «стор ↔ стор», и «стор ↔ файл»). Приметы только
// синтаксические, без os.Stat как в looksLikePath: иначе появившийся в текущей
// папке файл с именем инстанса молча превратил бы `sec diff svc prod` из
// сравнения инстансов в сверку с файлом — и дал ложное «всё сходится» перед
// прод-действием. Файл в текущей папке писать как ./имя.
func looksLikeEnvTarget(s string) bool {
	if _, _, ok := splitRemoteTarget(s); ok {
		return true
	}
	return strings.ContainsAny(s, `/\`) || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~")
}

func (t envTarget) remote() bool { return t.host != "" }

func (t envTarget) String() string {
	if t.remote() {
		return t.host + ":" + t.path
	}
	return t.path
}

// label — как называть цель в тексте сообщений («на хосте» / «в файле»).
func (t envTarget) label() string {
	if t.remote() {
		return "на хосте"
	}
	return "в файле"
}

// shell выполняет sh-скрипт там, где живёт файл: удалённо через ssh, локально
// через sh -c. Локальный путь без sudo сюда не заходит вовсе (см. read/write) —
// поэтому на Windows shell нужен только для явного --sudo, которого там нет.
// При sudo первый отказ по паролю разбирается интерактивно (sshSudoPrime) и
// команда повторяется один раз.
func (t envTarget) shell(sudo bool, script string, stdin []byte) ([]byte, error) {
	if sudo && !t.remote() && runtime.GOOS == "windows" {
		return nil, errors.New("--sudo для локального файла на Windows не работает (нет sudo и sh)")
	}
	run := func() ([]byte, string, error) {
		wrapped := sudoWrap(script, sudo)
		if t.remote() {
			return sshRun(t.host, wrapped, stdin)
		}
		return localShell(wrapped, stdin)
	}
	out, stderr, err := run()
	if err != nil && sudo && sudoNeedsPassword(stderr) {
		if t.remote() {
			if perr := sshSudoPrime(t.host); perr != nil {
				return nil, perr
			}
		} else if perr := localSudoPrime(); perr != nil {
			return nil, perr
		}
		out, _, err = run()
	}
	return out, err
}

// readMarker отделяет наш ответ от постороннего вывода: bash источает ~/.bashrc
// и для неинтерактивного `ssh host cmd`, так что любой echo/version-manager
// оттуда приезжает в stdout ПЕРЕД ответом. Без маркера этот мусор уехал бы в
// содержимое, а оттуда — обратно в прод-конфиг.
const readMarker = "__sec_env_file:"

// read отдаёт содержимое файла и признак его существования: отсутствие файла —
// не ошибка (deploy его создаст). Признак и содержимое приезжают в stdout, а не
// кодом возврата: код теряется по дороге через ssh + sudo + sh. Содержимое едет
// base64 — так маркер гарантированно не встречается внутри самого файла и
// граница «мусор / ответ» однозначна.
func (t envTarget) read(sudo bool) (data []byte, exists bool, err error) {
	if !t.remote() && !sudo {
		b, rerr := os.ReadFile(t.path)
		if errors.Is(rerr, os.ErrNotExist) {
			return nil, false, nil
		}
		if rerr != nil {
			return nil, false, rerr
		}
		return b, true, nil
	}
	q := shSingleQuote(t.path)
	script := fmt.Sprintf("if [ -e %s ]; then printf '%sy\\n'; base64 < %s; else printf '%sn\\n'; fi",
		q, readMarker, q, readMarker)
	out, err := t.shell(sudo, script, nil)
	if err != nil {
		return nil, false, err
	}
	i := bytes.LastIndex(out, []byte(readMarker))
	if i < 0 {
		return nil, false, fmt.Errorf("%s: непонятный ответ на чтение файла (на хосте нужен base64)", t)
	}
	rest := out[i+len(readMarker):]
	nl := bytes.IndexByte(rest, '\n')
	if nl < 1 {
		return nil, false, fmt.Errorf("%s: обрезанный ответ на чтение файла", t)
	}
	if rest[0] != 'y' {
		return nil, false, nil
	}
	// base64 переносит строки по 76 символов — Fields склеивает их обратно
	b, derr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(rest[nl+1:])), ""))
	if derr != nil {
		return nil, false, fmt.Errorf("%s: не удалось разобрать ответ хоста: %w", t, derr)
	}
	return b, true, nil
}

// write перезаписывает файл на месте, сохраняя владельца, права и inode: у
// прод-конфигов это принципиально, tmp+mv сделал бы файл нашим. Расплата —
// запись не атомарна, страховка от обрыва связи — бэкап, снятый до неё.
// Права 0600 навязываются только новому файлу (umask), существующему — никогда.
func (t envTarget) write(sudo bool, data []byte) error {
	if !t.remote() && !sudo {
		return writeFileKeepMode(t.path, data)
	}
	q := shSingleQuote(t.path)
	_, err := t.shell(sudo, fmt.Sprintf("umask 077 && cat > %s", q), data)
	return err
}

// backup копирует файл рядом с сохранением прав и владельца (cp -p).
func (t envTarget) backup(sudo bool, dst string) error {
	if !t.remote() && !sudo {
		return copyFileKeepMode(t.path, dst)
	}
	src, d := shSingleQuote(t.path), shSingleQuote(dst)
	_, err := t.shell(sudo, fmt.Sprintf("cp -p -- %s %s", src, d), nil)
	return err
}

// after выполняет команду пользователя там же, где лежит файл (рестарт сервиса),
// отдавая её вывод как есть. Под sudo не оборачивается: команда пишется целиком
// самим пользователем, sudo он поставит внутри, если нужен.
func (t envTarget) after(command string) error {
	if t.remote() {
		return sshStream(t.host, command)
	}
	cmd := localShellCmd(command)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// localShell — тот же контракт, что у sshRun, для файла на этой машине.
func localShell(script string, stdin []byte) ([]byte, string, error) {
	cmd := localShellCmd(script)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	var errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	stderr := strings.TrimSpace(errb.String())
	if err != nil && stderr != "" {
		err = fmt.Errorf("sh: %s", stderr)
	}
	return out.Bytes(), stderr, err
}

// localSudoPrime — локальный аналог sshSudoPrime: пароль вводится в sudo, а не
// в sec.
func localSudoPrime() error {
	if stdinPiped() {
		return errors.New("sudo требует пароль, а ввести его негде (stdin — не терминал): прогрей вручную `sudo -v`")
	}
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("не удалось получить право sudo: %w", err)
	}
	return nil
}

// copyFileKeepMode — локальный аналог `cp -p`: копия с правами оригинала, без
// зависимости от наличия sh и POSIX-cp (на Windows их нет).
func copyFileKeepMode(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, fi.Mode().Perm())
}

// writeFileKeepMode переписывает существующий файл, не трогая его права (в
// отличие от writeFile0600): deploy применяется к чужим конфигам, которые
// читает демон под своим пользователем. Новый файл создаётся под 0600.
func writeFileKeepMode(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
