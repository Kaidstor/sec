package command

// sec share — одноразовые/временные ссылки на секреты. Значение шифруется
// локально (internal/share), на сервер уходит только шифроблоб; ключ
// расшифровки живёт в URL-фрагменте и в аудит/сервер не попадает никогда.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/share"
	"github.com/kaidstor/sec/internal/store"

	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// shareConfigProject — служебный проект стора с адресом и токеном сервера.
// Имя не проходит projRe (первый символ не буквенно-цифровой), поэтому
// пользователь не может задеть его через set/rm/link — удаление только
// через `sec share setup --forget`.
const shareConfigProject = "_share"

func shareCommand(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "setup":
			return shareSetupCommand(args[1:])
		case "ls", "list":
			return shareLsCommand(args[1:])
		case "revoke":
			return shareRevokeCommand(args[1:])
		}
	}
	return shareCreateCommand(args)
}

// shareConfig — адрес и токен сервера: env SEC_SHARE_URL/SEC_SHARE_TOKEN
// поверх стора (_share/URL, _share/TOKEN). st может быть nil (стор недоступен,
// а конфиг целиком в env — например CI).
func shareConfig(st *store.Store) (baseURL, token string, ok bool) {
	baseURL = shareSetting(st, "SEC_SHARE_URL", "URL")
	token = shareSetting(st, "SEC_SHARE_TOKEN", "TOKEN")
	return baseURL, token, baseURL != "" && token != ""
}

// secondsRu — длительность в секундах с десятыми и запятой: «0,9 с».
func secondsRu(d time.Duration) string {
	return strings.Replace(fmt.Sprintf("%.1f с", d.Seconds()), ".", ",", 1)
}

// shareSetting — непустая env-переменная поверх _share/<key> из стора.
func shareSetting(st *store.Store, env, key string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	if st != nil {
		if s, ok := st.Projects[shareConfigProject][key]; ok {
			return mustText(s.Val)
		}
	}
	return ""
}

func mustShareClient(st *store.Store) *share.Client {
	baseURL, token, ok := shareConfig(st)
	if !ok {
		dieK(kindConfig, "сервер ссылок не настроен: sec share setup <url> (или env SEC_SHARE_URL/SEC_SHARE_TOKEN)")
	}
	checkShareURL(baseURL)
	return share.NewClient(baseURL, token)
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Host
	}
	return u
}

func shareCreateCommand(args []string) int {
	ref, rest := splitArgs(args)
	// одиночный "-" (stdin) flag-пакет считает позиционным и БРОСАЕТ разбор —
	// флаги после него молча терялись бы; вынимаем его до Parse
	if ref == "" && len(rest) > 0 && rest[0] == "-" {
		ref, rest = "-", rest[1:]
	}
	fs := newFlagSet("share")
	var ttlStr, fromFile, only string
	var multi, noClip, all bool
	fs.StringVar(&ttlStr, "ttl", "24h", "срок жизни ссылки 1h…7d (сгорает по времени, даже если не открыта)")
	fs.BoolVar(&multi, "multi", false, "многоразовая ссылка до истечения TTL (умолч. — одноразовая)")
	fs.StringVar(&fromFile, "file", "", "поделиться произвольным файлом с диска (вне стора)")
	fs.BoolVar(&noClip, "no-clip", false, "не копировать ссылку в буфер обмена")
	fs.BoolVar(&all, "all", false, "поделиться проектом целиком (пак: все ключи одной ссылкой)")
	fs.StringVar(&only, "only", "", "поделиться паком из перечисленных ключей (через запятую)")
	_ = fs.Parse(rest)
	// flag прекращает разбор на первом позиционном — всё после него пришло бы
	// сюда молча проигнорированным (например --multi после "-"); не молчим
	if ref == "" && fs.NArg() > 0 {
		ref = fs.Arg(0)
	} else if fs.NArg() > 0 {
		die("лишние аргументы после %q: %s — флаги ставь до позиционного аргумента",
			ref, strings.Join(fs.Args(), " "))
	}
	if trailing := fs.Args(); len(trailing) > 1 {
		die("лишние аргументы после %q: %s — флаги ставь до позиционного аргумента",
			trailing[0], strings.Join(trailing[1:], " "))
	}

	ttl, terr := parseHumanDuration(ttlStr)
	if terr != nil || ttl < time.Hour || ttl > 7*24*time.Hour {
		die("--ttl: интервал от 1h до 7d, например 24h или 3d (не %q)", ttlStr)
	}

	st, _, _, storeErr := store.Open(false)
	if storeErr != nil {
		st = nil // без стора работают только - и --file c env-конфигом
	}
	shortener := shareSetting(st, "SEC_SHARE_SHORTENER", "SHORTENER")
	var client *share.Client
	if ref == "-" { // ввод значения может длиться сколько угодно — снимок стора не держим
		client = mustShareClient(st)
		st.Close()
	}

	var env share.Envelope
	var target string // для аудита и сообщений; значений не содержит
	switch {
	case all || only != "":
		if fromFile != "" || ref == "-" {
			die("--all/--only собирают пак из стора — вместе с --file или - не работают")
		}
		if all && only != "" {
			die("--all и --only взаимоисключающие: либо весь проект, либо перечисленные ключи")
		}
		if strings.Contains(ref, "/") {
			die("пак — это проект целиком: sec share <proj> --all (без /KEY)")
		}
		if st == nil {
			dieStore(storeErr)
		}
		proj, _ := resolveServiceProj(ref, fs)
		keys := st.EffectiveKeys(proj)
		if len(keys) == 0 {
			dieNotFound("в проекте %s нет ключей (смотри: sec ls)", proj)
		}
		entries, perr := packEntries(keys, only)
		if perr != nil {
			die("%s: %v", proj, perr)
		}
		svc, _ := store.BaseAndProfile(proj)
		env = share.Envelope{Type: "pack", Project: svc, Entries: entries}
		target = fmt.Sprintf("%s (пак, %d ключей)", proj, len(entries))
	case fromFile != "":
		if ref != "" {
			die("sec share --file <путь> — без <proj>/<KEY>: файл берётся с диска, не из стора")
		}
		fi, serr := os.Stat(fromFile)
		if serr != nil {
			dieK(kindIO, "%v", serr)
		}
		if !fi.Mode().IsRegular() {
			die("%s — не обычный файл", fromFile)
		}
		if fi.Size() > maxFileSecret {
			die("%s: %d байт — больше предела %d МиБ", fromFile, fi.Size(), maxFileSecret>>20)
		}
		f, oerr := os.Open(fromFile)
		if oerr != nil {
			dieK(kindIO, "%v", oerr)
		}
		data, rerr := io.ReadAll(io.LimitReader(f, maxFileSecret+1))
		f.Close()
		if rerr != nil {
			dieK(kindIO, "%v", rerr)
		}
		if len(data) > maxFileSecret {
			die("%s: файл вырос при чтении — больше предела %d МиБ", fromFile, maxFileSecret>>20)
		}
		env = share.Envelope{
			Type:     "file",
			Filename: filepath.Base(fromFile),
			Mode:     fmt.Sprintf("%04o", fi.Mode().Perm()),
			Data:     data,
		}
		target = filepath.Base(fromFile)
	case ref == "-":
		var data []byte
		if stdinPiped() {
			var rerr error
			data, rerr = io.ReadAll(io.LimitReader(os.Stdin, maxFileSecret+1))
			if rerr != nil {
				dieK(kindIO, "stdin: %v", rerr)
			}
		} else {
			s, herr := readHidden("значение для ссылки: ")
			if herr != nil {
				dieK(kindIO, "%v", herr)
			}
			data = []byte(s)
		}
		data = []byte(strings.TrimRight(string(data), "\r\n"))
		if len(data) == 0 {
			die("пустое значение, ссылка не создана")
		}
		if len(data) > maxFileSecret {
			die("значение больше предела %d МиБ", maxFileSecret>>20)
		}
		env = share.Envelope{Type: "text", Data: data}
		target = "(stdin)"
	default:
		proj, key := resolveKeyRef(ref, fs, "sec share <proj>/<KEY> | - | --file <путь>")
		if st == nil {
			dieStore(storeErr)
		}
		sec, org, source, ok := st.Lookup(proj, key)
		if !ok {
			if org == store.OriginRef {
				dieK(kindConflict, "%s/%s ссылается на %s, но значения по цепочке нет (родитель удалён?)", proj, key, source)
			}
			dieNotFound("нет %s/%s (смотри: sec ls %s)", proj, key, proj)
		}
		raw, berr := sec.Bytes()
		if berr != nil {
			dieK(kindStore, "%s/%s: %v", proj, key, berr)
		}
		// файловые и бинарные секреты, в отличие от get --once, разрешены:
		// значение едет шифроблобом, в терминал не печатается
		if sec.IsFile() {
			name := key
			if sec.Meta != nil && sec.Meta.Filename != "" {
				if base := safeBaseName(sec.Meta.Filename); base != "" {
					name = base
				}
			}
			mode := "0600"
			if m, ok := storedFileMode(sec); ok {
				mode = fmt.Sprintf("%04o", m)
			}
			env = share.Envelope{Type: "file", Filename: name, Mode: mode, Data: raw}
		} else {
			env = share.Envelope{Type: "text", Data: raw}
		}
		target = proj + "/" + key
	}

	if client == nil {
		client = mustShareClient(st)
	}
	st.Close() // дальше сеть — снимок стора не держим
	started := time.Now()
	var k4tr *k4trProcess
	if shortener == "k4tr" {
		var kerr error
		if k4tr, kerr = startK4tr(ttl); kerr != nil {
			warnf("k4tr не запустился, ссылка будет полной: %v", kerr)
		}
	}
	key, err := share.NewKey()
	if err != nil {
		dieK(kindIO, "%v", err)
	}
	blob, err := share.Encode(key, env)
	if err != nil {
		dieK(kindIO, "%v", err)
	}
	id, expiresAt, err := client.Create(blob, ttl, !multi)
	if err != nil {
		dieShare(err)
	}
	link := share.SecretURL(client.BaseURL, id, key)
	longLink, shortAddr := link, ""
	var shortenTook time.Duration
	if k4tr != nil {
		base, fragment, _ := strings.Cut(link, "#")
		shortenStarted := time.Now()
		short, serr := k4tr.shorten(base)
		shortenTook = time.Since(shortenStarted)
		if serr != nil {
			warnf("k4tr не укоротил ссылку, отдаю полную: %v", serr)
		} else {
			link, shortAddr = short+"#"+fragment, short
		}
	}

	mode := "once"
	if multi {
		mode = "multi"
	}
	details := fmt.Sprintf("→ %s, id=%s, ttl=%s, %s", hostOf(client.BaseURL), id, ttlStr, mode)
	if shortAddr != "" {
		details += ", " + shortAddr
	}
	audit.Record("share", target, details)

	// URL — в stdout (подставляется в $(...)), пояснение — в stderr
	fmt.Fprintln(stdout, link)
	until := expiresAt.Local().Format("2006-01-02 15:04")
	msg := fmt.Sprintf("одноразовая ссылка: сгорит при первом открытии или %s", until)
	if multi {
		msg = fmt.Sprintf("многоразовая ссылка: живёт до %s", until)
	}
	if shortAddr != "" {
		msg += "; короткий адрес k4tr гаснет в тот же срок"
	}
	took := time.Since(started)
	msg += "; создана за " + secondsRu(took)
	if shortenTook > 0 {
		msg += " (k4tr " + secondsRu(shortenTook) + ")"
	}
	copied := false
	if !noClip {
		if cerr := clipboardWrite(link); cerr == nil {
			msg += "; скопирована в буфер обмена"
			copied = true
		}
	}
	if !jsonMode { // в JSON то же самое — поля expiresAt, once, clipboard
		fmt.Fprintln(os.Stderr, "sec: "+msg)
	}
	data := map[string]any{"url": link, "id": id, "target": target, "once": !multi,
		"expiresAt": expiresAt.Format(time.RFC3339), "clipboard": copied, "tookMs": took.Milliseconds()}
	if shortAddr != "" {
		data["longUrl"] = longLink
	}
	if shortenTook > 0 {
		data["shortenMs"] = shortenTook.Milliseconds()
	}
	emit(data)
	return 0
}

// k4trBinary ищет CLI k4tr: у приложения из Finder PATH без ~/.local/bin и brew.
func k4trBinary() (string, error) {
	if p, err := exec.LookPath("k4tr"); err == nil {
		return p, nil
	}
	candidates := []string{"/opt/homebrew/bin/k4tr", "/usr/local/bin/k4tr"}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append([]string{filepath.Join(home, ".local/bin/k4tr")}, candidates...)
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() {
			return c, nil
		}
	}
	return "", errors.New("k4tr не найден в PATH, ~/.local/bin и brew")
}

// k4trProcess — k4tr, запущенный до запроса к share-серверу: python, вход и
// TLS-соединение готовятся параллельно, адрес приходит через stdin. Если sec
// завершится раньше, k4tr получит EOF и ничего не создаст.
type k4trProcess struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   bytes.Buffer
}

func startK4tr(ttl time.Duration) (*k4trProcess, error) {
	bin, err := k4trBinary()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "create", "-", "--multi", "--ttl", strconv.Itoa(int(ttl.Seconds())), "--json")
	// k4tr с истёкшей сессией читает пароль через `sec get` — из того же
	// каталога, что и этот sec: у приложения из Finder brew нет в PATH.
	if self, err := os.Executable(); err == nil {
		cmd.Env = mergedEnv(map[string]string{"PATH": filepath.Dir(self) + string(os.PathListSeparator) + os.Getenv("PATH")})
	}
	p := &k4trProcess{cmd: cmd}
	cmd.Stdout = &p.out
	if p.stdin, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("k4tr: %v", err)
	}
	return p, nil
}

// shorten создаёт многоразовую короткую ссылку, которая гаснет вместе с
// share-ссылкой. Передавать только адрес без фрагмента: ключ расшифровки
// дописывается к короткой ссылке, а браузер при 302 без фрагмента в Location
// переносит исходный фрагмент на новый адрес.
func (p *k4trProcess) shorten(long string) (string, error) {
	_, werr := io.WriteString(p.stdin, long+"\n")
	p.stdin.Close()
	timer := time.AfterFunc(time.Minute, func() { p.cmd.Process.Kill() })
	runErr := p.cmd.Wait()
	timer.Stop()
	var resp struct {
		Data struct {
			ShortURL string `json:"short_url"`
		} `json:"data"`
		Error *failure `json:"error"`
	}
	if jerr := json.Unmarshal(p.out.Bytes(), &resp); jerr != nil {
		if runErr == nil {
			runErr = werr
		}
		if runErr != nil {
			return "", fmt.Errorf("k4tr: %v", runErr)
		}
		return "", fmt.Errorf("k4tr вернул не JSON: %v", jerr)
	}
	if resp.Error != nil {
		return "", errors.New(resp.Error.Message)
	}
	if !strings.HasPrefix(resp.Data.ShortURL, "https://") && !strings.HasPrefix(resp.Data.ShortURL, "http://") {
		return "", errors.New("k4tr не вернул короткую ссылку (проверь k4tr list)")
	}
	return resp.Data.ShortURL, nil
}

// packEntries собирает содержимое пака: текстовые значения как есть, файловые
// (kind: file и бинарные) — с именем и правами, чтобы получатель скачал их
// отдельными файлами, а не в .env. Суммарный размер ограничен тем же пределом,
// что одиночный файловый секрет.
func packEntries(keys map[string]store.Secret, only string) ([]share.PackEntry, error) {
	names := make([]string, 0, len(keys))
	if only == "" {
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
	} else {
		var missing []string
		for _, k := range strings.Split(only, ",") {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if _, ok := keys[k]; ok {
				names = append(names, k)
			} else {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("нет ключей: %s", strings.Join(missing, ", "))
		}
		if len(names) == 0 {
			return nil, errors.New("--only пуст — не из чего собирать пак")
		}
	}
	total := 0
	entries := make([]share.PackEntry, 0, len(names))
	for _, k := range names {
		sec := keys[k]
		raw, err := sec.Bytes()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		e := share.PackEntry{Key: k, Data: raw}
		if sec.Meta != nil {
			e.Kind = sec.Meta.Kind
		}
		if sec.IsFile() {
			e.Filename = k
			if sec.Meta != nil && sec.Meta.Filename != "" {
				if base := safeBaseName(sec.Meta.Filename); base != "" {
					e.Filename = base
				}
			}
			e.Mode = "0600"
			if m, ok := storedFileMode(sec); ok {
				e.Mode = fmt.Sprintf("%04o", m)
			}
		}
		total += len(raw)
		entries = append(entries, e)
	}
	if total > maxFileSecret {
		return nil, fmt.Errorf("суммарно %d байт — больше предела %d МиБ (сузь набор: --only)", total, maxFileSecret>>20)
	}
	return entries, nil
}

func shareSetupCommand(args []string) int {
	fs := newFlagSet("share setup")
	var forget bool
	var shortener string
	fs.BoolVar(&forget, "forget", false, "забыть сохранённые адрес и токен")
	fs.StringVar(&shortener, "shortener", "", "укорачивать ссылки: k4tr или none (выключить)")
	_ = fs.Parse(args)
	switch shortener {
	case "", "none":
	case "k4tr":
		if _, err := k4trBinary(); err != nil {
			dieK(kindConfig, "%v", err)
		}
	default:
		die("--shortener: k4tr или none (не %q)", shortener)
	}

	if forget {
		st, _, _, err := store.Begin(false)
		if err != nil {
			dieStore(err)
		}
		defer st.Close()
		if _, ok := st.Projects[shareConfigProject]; !ok {
			dieK(kindConfig, "share не настроен — забывать нечего")
		}
		delete(st.Projects, shareConfigProject)
		if err := st.Commit(); err != nil {
			dieK(kindStore, "запись хранилища: %v", err)
		}
		audit.Record("share-setup", "", "forget")
		fmt.Fprintln(stdout, "настройки share удалены из стора")
		emit(map[string]any{"forgotten": true})
		return 0
	}

	rawURL := fs.Arg(0)
	if rawURL == "" && shortener != "" {
		return shareSetShortener(shortener)
	}
	if rawURL == "" {
		die("укажи адрес: sec share setup <url> (или --shortener k4tr|none)")
	}
	baseURL := normalizeShareURL(rawURL)
	checkShareURL(baseURL)

	var token string
	if stdinPiped() {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			dieK(kindIO, "stdin: %v", err)
		}
		token = strings.TrimSpace(string(data))
	} else {
		t, err := readHidden("токен (выпускается на сервере: sec-share token add <имя>): ")
		if err != nil {
			dieK(kindIO, "%v", err)
		}
		token = strings.TrimSpace(t)
	}
	if token == "" {
		die("пустой токен, ничего не сохранено")
	}

	// проверка до сохранения: адрес достижим и токен принят
	if _, err := share.NewClient(baseURL, token).List(); err != nil {
		dieK(shareErrKind(err), "проверка не прошла: %v", err)
	}

	st, _, _, err := store.Begin(true)
	if err != nil {
		dieStore(err)
	}
	defer st.Close()
	keys := st.Project(shareConfigProject)
	store.Put(keys, "URL", baseURL)
	store.Put(keys, "TOKEN", token)
	putShortener(keys, shortener)
	if err := st.Commit(); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	details := ""
	if shortener != "" {
		details = "shortener=" + shortener
	}
	audit.Record("share-setup", hostOf(baseURL), details)
	fmt.Fprintf(stdout, "подключено: %s (токен в зашифрованном сторе)\n", baseURL)
	emit(map[string]any{"url": baseURL})
	return 0
}

func putShortener(keys map[string]store.Secret, shortener string) {
	switch shortener {
	case "none":
		delete(keys, "SHORTENER")
	case "k4tr":
		store.Put(keys, "SHORTENER", shortener)
	}
}

func shareSetShortener(shortener string) int {
	st, _, _, err := store.Begin(true)
	if err != nil {
		dieStore(err)
	}
	defer st.Close()
	keys, ok := st.Projects[shareConfigProject]
	if !ok && shortener != "none" {
		dieK(kindConfig, "share не настроен: сначала sec share setup <url>")
	}
	if ok {
		putShortener(keys, shortener)
	}
	if err := st.Commit(); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record("share-setup", "", "shortener="+shortener)
	if shortener == "none" {
		fmt.Fprintln(stdout, "укорачивание ссылок выключено")
	} else {
		fmt.Fprintf(stdout, "ссылки укорачиваются через %s: многоразовая короткая ссылка гаснет вместе с share-ссылкой\n", shortener)
	}
	emit(map[string]any{"shortener": shortener})
	return 0
}

// normalizeShareURL достраивает схему и срезает хвостовой слэш.
func normalizeShareURL(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	return strings.TrimRight(s, "/")
}

// checkShareURL: по голому http Bearer-токен уехал бы открытым текстом —
// разрешаем http только на loopback (локальная разработка).
func checkShareURL(baseURL string) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		die("не понял адрес сервера %q", baseURL)
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			die("по http токен уедет открытым текстом — нужен https (http разрешён только для localhost)")
		}
	}
}

func shareLsCommand(args []string) int {
	fs := newFlagSet("share ls")
	_ = fs.Parse(args)

	var st *store.Store
	if s, _, _, err := store.Open(false); err == nil {
		st = s
	}
	client := mustShareClient(st)
	st.Close()
	links, err := client.List()
	if err != nil {
		dieShare(err)
	}
	if jsonMode {
		type row struct {
			ID        string `json:"id"`
			CreatedAt string `json:"createdAt"`
			ExpiresAt string `json:"expiresAt"`
			Once      bool   `json:"once"`
			Claims    int    `json:"claims"`
		}
		rows := make([]row, 0, len(links))
		for _, l := range links {
			rows = append(rows, row{
				ID: l.ID, Once: l.Once, Claims: l.Claims,
				CreatedAt: l.CreatedAt.Format(time.RFC3339),
				ExpiresAt: l.ExpiresAt.Format(time.RFC3339),
			})
		}
		emit(rows)
		return 0
	}
	if len(links) == 0 {
		fmt.Fprintln(stdout, "активных ссылок нет")
		return 0
	}
	for _, l := range links {
		mode := "once"
		if !l.Once {
			mode = "multi"
		}
		fmt.Fprintf(stdout, "%-24s %s  до %s  %-5s просмотров: %d\n",
			l.ID,
			l.CreatedAt.Local().Format("2006-01-02 15:04"),
			l.ExpiresAt.Local().Format("2006-01-02 15:04"),
			mode, l.Claims)
	}
	warnf("URL восстановить нельзя — ключ расшифровки существовал только в момент создания")
	return 0
}

func shareRevokeCommand(args []string) int {
	fs := newFlagSet("share revoke")
	_ = fs.Parse(args)
	arg := fs.Arg(0)
	if arg == "" && stdinPiped() {
		// URL целиком = секрет: через stdin он не оседает в истории shell
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			dieK(kindIO, "stdin: %v", err)
		}
		arg = strings.TrimSpace(string(data))
	}
	if arg == "" {
		die("укажи ссылку или id: sec share revoke <id|url> (или URL через stdin: pbpaste | sec share revoke)")
	}
	id := share.IDFromURL(arg)
	if id == "" {
		die("не понял id в %q — короткую ссылку отзывай по id из sec share ls", arg)
	}
	var st *store.Store
	if s, _, _, err := store.Open(false); err == nil {
		st = s
	}
	client := mustShareClient(st)
	st.Close()
	if err := client.Revoke(id); err != nil {
		dieShare(err)
	}
	audit.Record("share-revoke", id, "")
	fmt.Fprintf(stdout, "ссылка %s отозвана\n", id)
	emit(map[string]any{"id": id, "revoked": true})
	return 0
}

// shareErrKind — класс ошибки share-сервера: не достучались (network),
// не принят токен (auth), прочий отказ сервера (api).
func shareErrKind(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return kindNetwork
	}
	var se *share.StatusError
	if errors.As(err, &se) && se.Code == 401 {
		return kindAuth
	}
	return kindAPI
}

func dieShare(err error) {
	dieK(shareErrKind(err), "%v", err)
}
