package command

// sec share — одноразовые/временные ссылки на секреты. Значение шифруется
// локально (internal/share), на сервер уходит только шифроблоб; ключ
// расшифровки живёт в URL-фрагменте и в аудит/сервер не попадает никогда.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/share"
	"github.com/kaidstor/sec/internal/store"

	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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
	baseURL, token = os.Getenv("SEC_SHARE_URL"), os.Getenv("SEC_SHARE_TOKEN")
	if st != nil {
		keys := st.Projects[shareConfigProject]
		if baseURL == "" {
			baseURL = keys["URL"].Value
		}
		if token == "" {
			token = keys["TOKEN"].Value
		}
	}
	return baseURL, token, baseURL != "" && token != ""
}

func mustShareClient(st *store.Store) *share.Client {
	baseURL, token, ok := shareConfig(st)
	if !ok {
		die("сервер ссылок не настроен: sec share setup <url> (или env SEC_SHARE_URL/SEC_SHARE_TOKEN)")
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
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	var ttlStr, fromFile, only string
	var multi, noClip, all bool
	fs.StringVar(&ttlStr, "ttl", "24h", "срок жизни ссылки 1h…7d (сгорает по времени, даже если не открыта)")
	fs.BoolVar(&multi, "multi", false, "многоразовая ссылка до истечения TTL (умолч. — одноразовая)")
	fs.StringVar(&fromFile, "file", "", "поделиться произвольным файлом с диска (вне стора)")
	fs.BoolVar(&noClip, "no-clip", false, "не копировать ссылку в буфер обмена")
	fs.BoolVar(&all, "all", false, "поделиться проектом целиком (пак: все ключи одной ссылкой)")
	fs.StringVar(&only, "only", "", "поделиться паком из перечисленных ключей (через запятую)")
	getEnv := addEnvFlag(fs)
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
			die("%v", storeErr)
		}
		proj, _ := resolveServiceProj(ref, fs, getEnv())
		keys := st.EffectiveKeys(proj)
		if len(keys) == 0 {
			die("в проекте %s нет ключей (смотри: sec ls)", store.RefToCLIProj(proj))
		}
		entries, perr := packEntries(keys, only)
		if perr != nil {
			die("%s: %v", store.RefToCLIProj(proj), perr)
		}
		svc, _ := store.BaseAndEnv(proj)
		env = share.Envelope{Type: "pack", Project: svc, Entries: entries}
		target = fmt.Sprintf("%s (пак, %d ключей)", proj, len(entries))
	case fromFile != "":
		if ref != "" {
			die("sec share --file <путь> — без <proj>/<KEY>: файл берётся с диска, не из стора")
		}
		fi, serr := os.Stat(fromFile)
		if serr != nil {
			die("%v", serr)
		}
		if !fi.Mode().IsRegular() {
			die("%s — не обычный файл", fromFile)
		}
		if fi.Size() > maxFileSecret {
			die("%s: %d байт — больше предела %d МиБ", fromFile, fi.Size(), maxFileSecret>>20)
		}
		f, oerr := os.Open(fromFile)
		if oerr != nil {
			die("%v", oerr)
		}
		data, rerr := io.ReadAll(io.LimitReader(f, maxFileSecret+1))
		f.Close()
		if rerr != nil {
			die("%v", rerr)
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
				die("stdin: %v", rerr)
			}
		} else {
			s, herr := readHidden("значение для ссылки: ")
			if herr != nil {
				die("%v", herr)
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
		proj, key := resolveKeyRef(ref, fs, getEnv(), "sec share <proj>/<KEY> | - | --file <путь>")
		if st == nil {
			die("%v", storeErr)
		}
		sec, org, source, ok := st.Lookup(proj, key)
		if !ok {
			if org == store.OriginRef {
				die("%s/%s ссылается на %s, но значения по цепочке нет (родитель удалён?)", proj, key, source)
			}
			die("нет %s/%s (смотри: sec ls %s)", proj, key, proj)
		}
		raw, berr := sec.Bytes()
		if berr != nil {
			die("%s/%s: %v", proj, key, berr)
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

	client := mustShareClient(st)
	key, err := share.NewKey()
	if err != nil {
		die("%v", err)
	}
	blob, err := share.Encode(key, env)
	if err != nil {
		die("%v", err)
	}
	id, expiresAt, err := client.Create(blob, ttl, !multi)
	if err != nil {
		die("%v", err)
	}
	link := share.SecretURL(client.BaseURL, id, key)

	mode := "once"
	if multi {
		mode = "multi"
	}
	audit.Record("share", target, fmt.Sprintf("→ %s, id=%s, ttl=%s, %s", hostOf(client.BaseURL), id, ttlStr, mode))

	// URL — в stdout (подставляется в $(...)), пояснение — в stderr
	fmt.Println(link)
	until := expiresAt.Local().Format("2006-01-02 15:04")
	msg := fmt.Sprintf("одноразовая ссылка: сгорит при первом открытии или %s", until)
	if multi {
		msg = fmt.Sprintf("многоразовая ссылка: живёт до %s", until)
	}
	if !noClip {
		if cerr := clipboardWrite(link); cerr == nil {
			msg += "; скопирована в буфер обмена"
		}
	}
	fmt.Fprintln(os.Stderr, "sec: "+msg)
	return 0
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
	fs := flag.NewFlagSet("share setup", flag.ExitOnError)
	var forget bool
	fs.BoolVar(&forget, "forget", false, "забыть сохранённые адрес и токен")
	_ = fs.Parse(args)

	if forget {
		unlock := store.Lock()
		defer unlock()
		st, mkey, _, err := store.Open(false)
		if err != nil {
			die("%v", err)
		}
		if _, ok := st.Projects[shareConfigProject]; !ok {
			die("share не настроен — забывать нечего")
		}
		delete(st.Projects, shareConfigProject)
		if err := store.Save(st, mkey); err != nil {
			die("запись хранилища: %v", err)
		}
		audit.Record("share-setup", "", "forget")
		fmt.Println("настройки share удалены из стора")
		return 0
	}

	rawURL := fs.Arg(0)
	if rawURL == "" {
		die("укажи адрес: sec share setup <url>")
	}
	baseURL := normalizeShareURL(rawURL)
	checkShareURL(baseURL)

	var token string
	if stdinPiped() {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			die("stdin: %v", err)
		}
		token = strings.TrimSpace(string(data))
	} else {
		t, err := readHidden("токен (выпускается на сервере: sec-share token add <имя>): ")
		if err != nil {
			die("%v", err)
		}
		token = strings.TrimSpace(t)
	}
	if token == "" {
		die("пустой токен, ничего не сохранено")
	}

	// проверка до сохранения: адрес достижим и токен принят
	if _, err := share.NewClient(baseURL, token).List(); err != nil {
		die("проверка не прошла: %v", err)
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(true)
	if err != nil {
		die("%v", err)
	}
	keys := st.Project(shareConfigProject)
	store.Put(keys, "URL", baseURL)
	store.Put(keys, "TOKEN", token)
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record("share-setup", hostOf(baseURL), "")
	fmt.Printf("подключено: %s (токен в зашифрованном сторе)\n", baseURL)
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
	fs := flag.NewFlagSet("share ls", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "машиночитаемый вывод")
	_ = fs.Parse(args)

	var st *store.Store
	if s, _, _, err := store.Open(false); err == nil {
		st = s
	}
	links, err := mustShareClient(st).List()
	if err != nil {
		die("%v", err)
	}
	if *jsonOut {
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
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
		return 0
	}
	if len(links) == 0 {
		fmt.Println("активных ссылок нет")
		return 0
	}
	for _, l := range links {
		mode := "once"
		if !l.Once {
			mode = "multi"
		}
		fmt.Printf("%-24s %s  до %s  %-5s просмотров: %d\n",
			l.ID,
			l.CreatedAt.Local().Format("2006-01-02 15:04"),
			l.ExpiresAt.Local().Format("2006-01-02 15:04"),
			mode, l.Claims)
	}
	fmt.Fprintln(os.Stderr, "sec: URL восстановить нельзя — ключ расшифровки существовал только в момент создания")
	return 0
}

func shareRevokeCommand(args []string) int {
	fs := flag.NewFlagSet("share revoke", flag.ExitOnError)
	_ = fs.Parse(args)
	arg := fs.Arg(0)
	if arg == "" && stdinPiped() {
		// URL целиком = секрет: через stdin он не оседает в истории shell
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			die("stdin: %v", err)
		}
		arg = strings.TrimSpace(string(data))
	}
	if arg == "" {
		die("укажи ссылку или id: sec share revoke <id|url> (или URL через stdin: pbpaste | sec share revoke)")
	}
	id := share.IDFromURL(arg)
	if id == "" {
		die("не понял id в %q", arg)
	}
	var st *store.Store
	if s, _, _, err := store.Open(false); err == nil {
		st = s
	}
	if err := mustShareClient(st).Revoke(id); err != nil {
		die("%v", err)
	}
	audit.Record("share-revoke", id, "")
	fmt.Printf("ссылка %s отозвана\n", id)
	return 0
}
