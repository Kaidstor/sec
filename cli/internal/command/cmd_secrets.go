package command

// Команды над отдельными ключами: set / gen / get / history / undo / mv / rm / otp.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/store"
	"github.com/kaidstor/sec/internal/totp"

	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// maxFileSecret — предел размера файлового секрета: стор целиком живёт в
// памяти и JSON, история держит до 5 версий — большие блобы его раздуют.
const maxFileSecret = 4 << 20

func setCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := newFlagSet("set")
	var fromClip, clearClip, fromStdin, override bool
	var note, kind, fromFile string
	fs.BoolVar(&fromClip, "clipboard", false, "взять значение из буфера обмена")
	fs.BoolVar(&clearClip, "clear", false, "очистить буфер после сохранения (с --clipboard)")
	fs.BoolVar(&fromStdin, "stdin", false, "читать значение из stdin")
	fs.StringVar(&fromFile, "from-file", "", "взять значение из файла как есть (сертификат/ключ; бинарные — в base64)")
	fs.BoolVar(&override, "override", false, "перебить ссылку/наследование собственным значением")
	fs.StringVar(&note, "note", "", "описание/назначение ключа (метаданные, без секрета)")
	fs.StringVar(&kind, "kind", "", "тип: password|apikey|totp|file|config|env|...")
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, "sec set <proj>/<KEY> (или просто <KEY> внутри папки проекта)")

	// ссылку/наследование не редактируем — предупреждаем до ввода, чтобы не тратить набор впустую
	if st0, _, _, err := store.Open(false); err == nil {
		mustEditable(st0, proj, key, override)
	}

	var val, enc, fileName, fileMode string
	var err error
	src := "скрытый ввод"
	switch {
	case fromFile != "":
		if fromClip || fromStdin {
			die("--from-file несовместим с --clipboard/--stdin")
		}
		// тип файла проверяем ДО открытия: os.Open на FIFO без писателя виснет
		// навсегда; девайсы/пайпы к тому же обходят лимит (у них Size()==0)
		if fi, serr := os.Stat(fromFile); serr != nil {
			dieK(kindIO, "чтение %s: %v", fromFile, serr)
		} else if !fi.Mode().IsRegular() {
			die("%s — не обычный файл (%v): --from-file читает только файлы", fromFile, fi.Mode().Type())
		}
		f, oerr := os.Open(fromFile)
		if oerr != nil {
			dieK(kindIO, "чтение %s: %v", fromFile, oerr)
		}
		// fstat уже открытого файла — путь могли подменить между Stat и Open;
		// чтение с жёстким потолком — файл мог вырасти после проверки размера
		fi, serr := f.Stat()
		if serr != nil {
			dieK(kindIO, "чтение %s: %v", fromFile, serr)
		}
		if !fi.Mode().IsRegular() {
			die("%s — не обычный файл (%v): --from-file читает только файлы", fromFile, fi.Mode().Type())
		}
		if fi.Size() > maxFileSecret {
			die("%s: %d байт — больше предела %d МиБ (стор целиком живёт в памяти и истории)",
				fromFile, fi.Size(), maxFileSecret>>20)
		}
		data, rerr := io.ReadAll(io.LimitReader(f, maxFileSecret+1))
		f.Close()
		if rerr != nil {
			dieK(kindIO, "чтение %s: %v", fromFile, rerr)
		}
		if len(data) > maxFileSecret {
			die("%s: файл вырос при чтении — больше предела %d МиБ", fromFile, maxFileSecret>>20)
		}
		if len(data) == 0 {
			die("файл %s пуст, ничего не сохранено", fromFile)
		}
		fileName = filepath.Base(fromFile)
		fileMode = fmt.Sprintf("%04o", fi.Mode().Perm())
		src = "файл " + fileName
		if isBinaryData(data) {
			val, enc = base64.StdEncoding.EncodeToString(data), store.EncB64
		} else {
			val = string(data) // текстовый файл — байты как есть, без трима
		}
	case fromClip:
		src = "буфер обмена"
		val, err = clipboardRead()
		if err != nil {
			dieK(kindIO, "буфер обмена: %v", err)
		}
	case fromStdin || stdinPiped():
		src = "stdin"
		data, rerr := io.ReadAll(os.Stdin)
		if rerr != nil {
			dieK(kindIO, "stdin: %v", rerr)
		}
		val = string(data)
	default:
		val, err = readHidden(fmt.Sprintf("значение %s/%s: ", proj, key))
		if err != nil {
			dieK(kindIO, "%v", err)
		}
		again, aerr := readHidden("повтори: ")
		if aerr != nil {
			dieK(kindIO, "%v", aerr)
		}
		if val != again {
			die("значения не совпали, ничего не сохранено")
		}
	}
	if fromFile == "" { // файл сохраняем байт-в-байт, остальным источникам — трим хвостового перевода строки
		val = strings.TrimRight(val, "\r\n")
	}
	if val == "" {
		die("пустое значение, ничего не сохранено")
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(true)
	if err != nil {
		dieStore(err)
	}
	mustEditable(st, proj, key, override) // авторитетная проверка под блокировкой
	keys := st.Project(proj)
	if override { // перебиваем ссылку — сносим её начисто, без пустой истории
		if cur, ok := keys[key]; ok && cur.Ref != "" {
			delete(keys, key)
		}
	}
	existed := store.PutEnc(keys, key, val, enc)
	applyMetaFlags(keys, key, note, kind)
	if fileName != "" {
		applyFileMeta(keys, key, fileName, fileMode)
	} else {
		clearFileMeta(keys, key) // текст поверх файлового секрета — прежнее имя файла больше не о нём
	}
	if err := store.Save(st, mkey); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record("set", proj+"/"+key, src)
	verb := "сохранён"
	if existed {
		verb = "обновлён (прежнее значение в истории — sec undo вернёт)"
	}
	size := fmt.Sprintf("%d символов", len(val))
	out := map[string]any{"ref": proj + "/" + key, "updated": existed, "chars": len(val)}
	if enc == store.EncB64 {
		raw, _ := (store.Secret{Value: val, Enc: enc}).Bytes()
		size = fmt.Sprintf("бинарный файл, %d байт → base64", len(raw))
		delete(out, "chars")
		out["binary"], out["bytes"] = true, len(raw)
	}
	fmt.Fprintf(stdout, "%s/%s %s (%s, значение скрыто)\n", proj, key, verb, size)
	printDupeHints(st, mkey, proj, key)
	if fromClip && clearClip {
		if err := clipboardWrite(""); err == nil {
			fmt.Fprintln(stdout, "буфер обмена очищен")
			out["clipboardCleared"] = true
		}
	}
	emit(out)
	return 0
}

// isBinaryData — байты не годятся как текстовое значение (не-UTF-8 или NUL) —
// хранить только как base64.
func isBinaryData(data []byte) bool {
	return !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0
}

// applyFileMeta помечает ключ файловым: имя исходного файла (для get --out в
// каталог), его права (get --out их восстановит) и kind=file, если тип не
// задан явно.
func applyFileMeta(keys map[string]store.Secret, key, fileName, fileMode string) {
	e := keys[key]
	m := store.Meta{}
	if e.Meta != nil {
		m = *e.Meta
	}
	if m.Kind == "" {
		m.Kind = "file"
	}
	m.Filename = fileName
	m.FileMode = fileMode
	e.Meta = &m
	keys[key] = e
}

// clearFileMeta снимает файловую метку при перезаписи ключа текстовым значением:
// иначе get --out <каталог> положил бы новый текст под именем старого
// сертификата, а ls показывал бы «file, server.p12» про обычный токен.
func clearFileMeta(keys map[string]store.Secret, key string) {
	e := keys[key]
	if e.Meta == nil || e.Meta.Filename == "" {
		return
	}
	m := *e.Meta
	m.Filename = ""
	m.FileMode = ""
	if m.Kind == "file" {
		m.Kind = ""
	}
	if m == (store.Meta{}) {
		e.Meta = nil
	} else {
		e.Meta = &m
	}
	keys[key] = e
}

const (
	genAlnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	genSymbols = "!@#$%^&*()-_=+[]{}:,.?"
)

// genCommand генерирует криптостойкий секрет и сохраняет, не показывая —
// агент может заводить новые пароли/токены, вообще не зная их значения.
func genCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := newFlagSet("gen")
	var length int
	var symbols, clip, override bool
	var note, kind string
	fs.IntVar(&length, "len", 32, "длина значения")
	fs.BoolVar(&symbols, "symbols", false, "добавить спецсимволы к буквам/цифрам")
	fs.BoolVar(&clip, "clip", false, "скопировать значение в буфер обмена")
	fs.BoolVar(&override, "override", false, "перебить ссылку/наследование собственным значением")
	fs.StringVar(&note, "note", "", "описание/назначение ключа (метаданные, без секрета)")
	fs.StringVar(&kind, "kind", "", "тип: password|apikey|totp|config|env|...")
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, "sec gen <proj>/<KEY> [--len 32]")
	if length < 8 || length > 1024 {
		die("--len: от 8 до 1024")
	}

	charset := genAlnum
	if symbols {
		charset += genSymbols
	}
	val := make([]byte, length)
	for i := range val {
		n, err := crand.Int(crand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			dieK(kindIO, "rand: %v", err)
		}
		val[i] = charset[n.Int64()]
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(true)
	if err != nil {
		dieStore(err)
	}
	mustEditable(st, proj, key, override)
	keys := st.Project(proj)
	if override {
		if cur, ok := keys[key]; ok && cur.Ref != "" {
			delete(keys, key)
		}
	}
	existed := store.Put(keys, key, string(val))
	applyMetaFlags(keys, key, note, kind)
	clearFileMeta(keys, key) // gen поверх файлового секрета — имя файла больше не о нём
	if err := store.Save(st, mkey); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record("gen", proj+"/"+key, fmt.Sprintf("len=%d", length))
	verb := "сгенерирован и сохранён"
	if existed {
		verb = "перегенерирован (прежнее значение в истории — sec undo вернёт)"
	}
	fmt.Fprintf(stdout, "%s/%s %s (%d символов, значение скрыто)\n", proj, key, verb, length)
	printDupeHints(st, mkey, proj, key)
	if clip {
		if err := clipboardWrite(string(val)); err != nil {
			dieK(kindIO, "буфер обмена: %v", err)
		}
		fmt.Fprintln(stdout, "значение в буфере обмена — вставь куда нужно")
	}
	emit(map[string]any{"ref": proj + "/" + key, "updated": existed, "chars": length, "clipboard": clip})
	return 0
}

func getCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := newFlagSet("get")
	var clip, peek, fp, once bool
	var prevN int
	fs.BoolVar(&clip, "clip", false, "скопировать в буфер обмена, не печатать")
	fs.BoolVar(&peek, "peek", false, "показать маску ab…yz и длину вместо значения")
	fs.BoolVar(&fp, "fingerprint", false, "показать отпечаток fp:… (безопасно для чата)")
	fs.BoolVar(&once, "once", false, "показать значение и сразу удалить ключ (одноразовая передача)")
	var clearAfter, outFile string
	fs.StringVar(&clearAfter, "clear-after", "", "с --clip: очистить буфер через интервал (напр. 20s), если не перезаписан")
	fs.StringVar(&outFile, "out", "", "записать значение в файл 0600 (единственный способ достать бинарные); без пути — в текущую папку под исходным именем")
	fs.IntVar(&prevN, "prev", 0, "показать N-е предыдущее значение (1 = прошлое)")
	// голый --out (без пути) — «сюда, под исходным именем»: стандартный flag
	// опциональных значений не умеет, подставляем "." сами
	rest = defaultBareFlag(rest, "out", ".")
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, "sec get <proj>/<KEY>")

	st, mkey, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	sec, org, source, ok := st.Lookup(proj, key)
	if !ok {
		if org == store.OriginRef {
			dieK(kindConflict, "%s/%s ссылается на %s, но значения по цепочке нет (родитель удалён?)", proj, key, source)
		}
		dieNotFound("нет %s/%s (смотри: sec ls %s)", proj, key, proj)
	}
	val, enc := sec.Value, sec.Enc
	detail := "показано"
	if prevN > 0 {
		if prevN > len(sec.History) {
			dieK(kindConflict, "у %s/%s в истории только %d значений (sec history %s)", proj, key, len(sec.History), ref)
		}
		val, enc = sec.History[prevN-1].Value, sec.History[prevN-1].Enc
		detail = fmt.Sprintf("показано prev=%d", prevN)
	}
	if outFile != "" {
		if once || clip || peek || fp {
			die("--out несовместим с --once/--clip/--peek/--fingerprint")
		}
		raw, berr := (store.Secret{Value: val, Enc: enc}).Bytes()
		if berr != nil {
			dieK(kindStore, "%s/%s: %v", proj, key, berr)
		}
		target := outFile
		if fi, serr := os.Stat(outFile); serr == nil && fi.IsDir() {
			name := key // в каталог — под исходным именем файла, если оно известно
			if sec.Meta != nil && sec.Meta.Filename != "" {
				// Filename мог приехать из чужого стора (sync/restore) и содержать
				// разделители любой ОС — в путь идёт только простое имя, без
				// возможности выйти из каталога
				if base := safeBaseName(sec.Meta.Filename); base != "" {
					name = base
				}
			}
			target = filepath.Join(outFile, name)
		}
		if werr := writeSecretFile(target, raw); werr != nil {
			dieK(kindIO, "запись %s: %v", target, werr)
		}
		modeLabel := "0600"
		if _, _, isRemote := splitRemoteTarget(target); !isRemote {
			// исходные права файла (set --from-file) — для .pub/конфигов 0600 не то;
			// по ssh не восстанавливаем: там фиксированный chmod 600 (remote.go)
			if mode, ok := storedFileMode(sec); ok && mode != 0o600 {
				if cerr := os.Chmod(target, mode); cerr == nil {
					modeLabel = fmt.Sprintf("%04o, исходные права", mode)
				}
			}
		}
		audit.Record("get", proj+"/"+key, strings.Replace(detail, "показано", "→ файл "+target, 1))
		fmt.Fprintf(stdout, "записан %s (%s, %d байт) — файл вне шифрованного стора, не коммить\n", target, modeLabel, len(raw))
		emit(getData(proj, key, prevN, map[string]any{"file": target, "mode": strings.TrimSuffix(modeLabel, ", исходные права"), "bytes": len(raw)}))
		return 0
	}
	isBin := enc == store.EncB64
	if fp {
		audit.Record("get", proj+"/"+key, "отпечаток")
		fmt.Fprintln(stdout, store.Fingerprint(mkey, val))
		emit(getData(proj, key, prevN, map[string]any{"fingerprint": store.Fingerprint(mkey, val)}))
		return 0
	}
	if once {
		if prevN > 0 {
			die("--once несовместим с --prev")
		}
		if isBin {
			die("%s/%s — бинарный (файловый) секрет, в терминал/буфер не отдаётся;\n"+
				"    достань файлом и удали ключ вручную: sec get %s --out <файл> && sec rm %s",
				proj, key, ref, ref)
		}
		if org != store.OriginOwn {
			dieK(kindConflict, "%s/%s не собственное значение (%s) — --once уничтожил бы ссылку, а значение осталось бы в родителе", proj, key, source)
		}
		unlock := store.Lock()
		defer unlock()
		st2, mkey2, _, err := store.Open(false)
		if err != nil {
			dieStore(err)
		}
		if _, ok := st2.Projects[proj][key]; !ok {
			dieNotFound("нет %s/%s", proj, key)
		}
		if refs := st2.Referrers(proj + "/" + key); len(refs) > 0 {
			warnf("ВНИМАНИЕ: на %s/%s ссылаются %s — после --once удаления ссылки станут битыми", proj, key, strings.Join(refs, ", "))
		}
		// буфер — до удаления: если он недоступен, ключ остаётся в сторе,
		// иначе значение потерялось бы безвозвратно
		if clip {
			if err := clipboardWrite(val); err != nil {
				dieK(kindIO, "буфер обмена: %v (ключ не удалён)", err)
			}
		}
		delete(st2.Projects[proj], key)
		st2.Prune(proj)
		if err := store.Save(st2, mkey2); err != nil {
			dieK(kindStore, "запись хранилища: %v", err)
		}
		out := map[string]any{"deleted": true}
		if clip {
			audit.Record("get", proj+"/"+key, "once (в буфер и удалено)")
			fmt.Fprintln(stdout, "скопировано в буфер обмена (значение не показано)")
			out["clipboard"] = true
		} else {
			audit.Record("get", proj+"/"+key, "once (показано и удалено)")
			fmt.Fprintln(stdout, val)
			out["value"] = val
		}
		if !jsonMode { // в JSON это поле deleted
			warnf("%s/%s удалён после одноразового показа", proj, key)
		}
		emit(getData(proj, key, 0, out))
		return 0
	}
	if peek {
		audit.Record("get", proj+"/"+key, strings.Replace(detail, "показано", "маска", 1))
		if isBin {
			raw, _ := (store.Secret{Value: val, Enc: enc}).Bytes()
			fmt.Fprintf(stdout, "%s (бинарный файл, %d байт — sec get %s --out <файл>)\n", store.MaskValue(val), len(raw), ref)
			emit(getData(proj, key, prevN, map[string]any{"mask": store.MaskValue(val), "binary": true, "bytes": len(raw)}))
			return 0
		}
		fmt.Fprintf(stdout, "%s (%d символов)\n", store.MaskValue(val), len([]rune(val)))
		emit(getData(proj, key, prevN, map[string]any{"mask": store.MaskValue(val), "chars": len([]rune(val))}))
		return 0
	}
	if clip {
		if isBin {
			die("%s/%s — бинарный (файловый) секрет, в буфер обмена не копируется: sec get %s --out <файл>", proj, key, ref)
		}
		if err := clipboardWrite(val); err != nil {
			dieK(kindIO, "буфер обмена: %v", err)
		}
		msg := "скопировано в буфер обмена (значение не показано)"
		out := map[string]any{"clipboard": true}
		if clearAfter != "" {
			d, derr := parseHumanDuration(clearAfter)
			if derr != nil || d <= 0 {
				die("--clear-after: некорректный интервал %q", clearAfter)
			}
			secs := int(d.Seconds())
			if secs < 1 {
				secs = 1
			}
			if err := spawnClipboardClear(val, secs); err != nil {
				warnf("авто-очистка буфера не запущена: %v", err)
			} else {
				msg += "; очистится через " + clearAfter + ", если не перезапишешь"
				out["clearAfter"] = clearAfter
			}
		}
		audit.Record("get", proj+"/"+key, strings.Replace(detail, "показано", "в буфер", 1))
		fmt.Fprintln(stdout, msg)
		emit(getData(proj, key, prevN, out))
		return 0
	}
	if isBin {
		die("%s/%s — бинарный (файловый) секрет, сырые байты в терминал не печатаются: sec get %s --out <файл>", proj, key, ref)
	}
	audit.Record("get", proj+"/"+key, detail)
	fmt.Fprintln(stdout, val)
	emit(getData(proj, key, prevN, map[string]any{"value": val}))
	return 0
}

// getData — data конверта get: адрес, номер версии из истории (--prev) и то,
// что команда отдала. Значение (value) — только там, где get печатает его и в
// тексте: голый get и --once без --clip.
func getData(proj, key string, prev int, fields map[string]any) map[string]any {
	fields["ref"] = proj + "/" + key
	if prev > 0 {
		fields["prev"] = prev
	}
	return fields
}

// historyCommand показывает версии значения маскированно (peek + длина + дата).
func historyCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := newFlagSet("history")
	asJSON := jsonMode
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, "sec history <proj>/<KEY>")
	st, mkey, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	sec, org, source, ok := st.Lookup(proj, key)
	if !ok {
		dieNotFound("нет %s/%s", proj, key)
	}
	if org != store.OriginOwn && !asJSON {
		fmt.Fprintf(stdout, "%s/%s — значение из %s (по ссылке/наследованию), история ниже — родителя\n", proj, key, source)
	}
	if asJSON {
		type verOut struct {
			Pos         int    `json:"pos"` // +N — отменённое (redo), 0 — текущее, -N — история
			Fingerprint string `json:"fingerprint"`
			Chars       int    `json:"chars"`
			UpdatedAt   string `json:"updatedAt"`
		}
		out := []verOut{}
		for i := len(sec.RedoStack) - 1; i >= 0; i-- {
			v := sec.RedoStack[i]
			out = append(out, verOut{i + 1, store.Fingerprint(mkey, v.Value), len([]rune(v.Value)), v.UpdatedAt})
		}
		out = append(out, verOut{0, store.Fingerprint(mkey, sec.Value), len([]rune(sec.Value)), sec.UpdatedAt})
		for i, v := range sec.History {
			out = append(out, verOut{-(i + 1), store.Fingerprint(mkey, v.Value), len([]rune(v.Value)), v.UpdatedAt})
		}
		emit(out)
		return 0
	}
	fmt.Fprintf(stdout, "%s/%s — версий: %d\n", proj, key, 1+len(sec.History)+len(sec.RedoStack))
	// «будущее» (отменённое через undo) — сверху, самое дальнее первым.
	for i := len(sec.RedoStack) - 1; i >= 0; i-- {
		v := sec.RedoStack[i]
		fmt.Fprintf(stdout, "  %+3d  %-8s %4d симв.  %s  (отменено, sec redo вернёт)\n",
			i+1, store.MaskValue(v.Value), len([]rune(v.Value)), fmtTime(v.UpdatedAt))
	}
	fmt.Fprintf(stdout, "  тек  %-8s %4d симв.  %s\n", store.MaskValue(sec.Value), len([]rune(sec.Value)), fmtTime(sec.UpdatedAt))
	for i, v := range sec.History {
		fmt.Fprintf(stdout, "  %3d  %-8s %4d симв.  %s\n", -(i + 1), store.MaskValue(v.Value), len([]rune(v.Value)), fmtTime(v.UpdatedAt))
	}
	return 0
}

// undoCommand шагает на одну версию назад: History[0] становится текущим,
// вытесненное текущее уходит в redo-стек. Повторный undo идёт глубже в прошлое
// и упирается в стену, когда история кончилась; sec redo возвращает вперёд.
func undoCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := newFlagSet("undo")
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, "sec undo <proj>/<KEY>")
	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	mustEditable(st, proj, key, false) // у ссылки/наследования своей истории нет — она у родителя
	next, ok := mustSecret(st, proj, key).Undo()
	if !ok {
		dieK(kindConflict, "у %s/%s нет более старых версий (sec history %s)", proj, key, ref)
	}
	st.Projects[proj][key] = next
	if err := store.Save(st, mkey); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record("undo", proj+"/"+key, "")
	fmt.Fprintf(stdout, "%s/%s ← версия от %s (%d символов); ещё старше: %d, вернуть вперёд: sec redo\n",
		proj, key, fmtTime(next.UpdatedAt), len([]rune(next.Value)), len(next.History))
	emit(map[string]any{"ref": proj + "/" + key, "updatedAt": next.UpdatedAt, "chars": len([]rune(next.Value)),
		"older": len(next.History), "ahead": len(next.RedoStack)})
	return 0
}

// redoCommand — обратная к undo: возвращает ближайшее отменённое значение.
func redoCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := newFlagSet("redo")
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, "sec redo <proj>/<KEY>")
	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	mustEditable(st, proj, key, false)
	next, ok := mustSecret(st, proj, key).Redo()
	if !ok {
		dieK(kindConflict, "у %s/%s нет отменённых значений впереди (redo нечего возвращать)", proj, key)
	}
	st.Projects[proj][key] = next
	if err := store.Save(st, mkey); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record("redo", proj+"/"+key, "")
	fmt.Fprintf(stdout, "%s/%s → версия от %s (%d символов); ещё впереди: %d\n",
		proj, key, fmtTime(next.UpdatedAt), len([]rune(next.Value)), len(next.RedoStack))
	emit(map[string]any{"ref": proj + "/" + key, "updatedAt": next.UpdatedAt, "chars": len([]rune(next.Value)),
		"older": len(next.History), "ahead": len(next.RedoStack)})
	return 0
}

// forgetCommand вычищает историю и redo ключа, оставляя текущее значение.
// Нужен после ротации скомпрометированного секрета: обычный set утаскивает
// старое (утёкшее) значение в историю — forget убирает его из хранилища.
func forgetCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := newFlagSet("forget")
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, "sec forget <proj>/<KEY>")
	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	mustEditable(st, proj, key, false)
	cur := mustSecret(st, proj, key)
	n := len(cur.History) + len(cur.RedoStack)
	if n == 0 {
		fmt.Fprintf(stdout, "%s/%s: прошлых версий нет, чистить нечего\n", proj, key)
		emit(map[string]any{"ref": proj + "/" + key, "removed": 0})
		return 0
	}
	st.Projects[proj][key] = cur.Forget()
	if err := store.Save(st, mkey); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record("forget", proj+"/"+key, fmt.Sprintf("удалено версий: %d", n))
	fmt.Fprintf(stdout, "%s/%s: удалено прошлых версий: %d (текущее значение осталось)\n", proj, key, n)
	emit(map[string]any{"ref": proj + "/" + key, "removed": n})
	return 0
}

// mvCommand переносит/переименовывает ключ, cpCommand копирует — вся логика
// общая (moveKey), отличается только удалением оригинала.
func mvCommand(args []string) int { return moveKey(args, true) }
func cpCommand(args []string) int { return moveKey(args, false) }

// moveKey переносит (remove=true) или копирует (remove=false) ключ без
// раскрытия значения — вместе едут история, redo и метаданные. Назначение без
// "/" — имя проекта, имя ключа сохраняется (переименование внутри проекта:
// sec mv demo/OLD demo/NEW). Назначение без явного '@' наследует профиль
// источника; свой профиль — proj2@prof, базовый набор — proj2@.
func moveKey(args []string, remove bool) int {
	name := "cp"
	if remove {
		name = "mv"
	}
	fs := newFlagSet(name)
	var force bool
	fs.BoolVar(&force, "force", false, "перезаписать существующий ключ назначения")
	pos := collectPositionals(fs, args)
	if len(pos) != 2 {
		die("нужно два аргумента: sec %s <proj>/<KEY> <proj2>[/<KEY2>]", name)
	}
	sp, sk, profile := resolveRefP(pos[0])
	var dp, dk string
	if strings.Contains(pos[1], "/") {
		dp, dk = resolveRelRef(pos[1], profile)
	} else {
		dp, dk = resolveRelProj(pos[1], profile), sk
	}
	if sp == dp && sk == dk {
		die("источник и назначение совпадают")
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	s := mustSecret(st, sp, sk)
	if _, busy := st.Projects[dp][dk]; busy && !force {
		dieK(kindConflict, "%s/%s уже существует — sec %s --force перезапишет", dp, dk, name)
	}
	st.Project(dp)[dk] = s
	note := "копия, оригинал на месте, значение не показано"
	if remove {
		delete(st.Projects[sp], sk)
		st.Prune(sp)
		note = "история сохранена, значение не показано"
	}
	if err := store.Save(st, mkey); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record(name, sp+"/"+sk, "→ "+dp+"/"+dk)
	fmt.Fprintf(stdout, "%s/%s → %s/%s (%s)\n", sp, sk, dp, dk, note)
	emit(map[string]any{"from": sp + "/" + sk, "to": dp + "/" + dk, "moved": remove})
	return 0
}

func rmCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := newFlagSet("rm")
	var all bool
	fs.BoolVar(&all, "all", false, "удалить проект целиком")
	_ = fs.Parse(rest)
	if ref == "" {
		ref = fs.Arg(0)
	}
	if ref == "" {
		die("укажи ключ (sec rm <proj>/<KEY>) или проект (sec rm <proj> --all)")
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	if all {
		if strings.Contains(ref, "/") {
			die("--all принимает имя проекта, а не ключ: sec rm %s --all", strings.Split(ref, "/")[0])
		}
		sp := resolveProj(ref)
		n := len(st.Projects[sp])
		if n == 0 {
			dieNotFound("проекта %q нет", sp)
		}
		if refs := st.ProjectReferrers(sp); len(refs) > 0 {
			warnf("ВНИМАНИЕ: на ключи %s ссылаются %s — после удаления ссылки станут битыми", sp, strings.Join(refs, ", "))
		}
		if ext := st.Extenders(sp); len(ext) > 0 {
			warnf("ВНИМАНИЕ: от %s наследуют %s — потеряют унаследованные ключи (отвязать: sec extend <proj> --remove %s)", sp, strings.Join(ext, ", "), st.DisplayProj(sp))
		}
		delete(st.Projects, sp)
		delete(st.Extends, sp) // осиротевшие исходящие связи удаляемого проекта
		if err := store.Save(st, mkey); err != nil {
			dieK(kindStore, "запись хранилища: %v", err)
		}
		audit.Record("rm", sp, fmt.Sprintf("проект целиком (%d ключей)", n))
		fmt.Fprintf(stdout, "удалён проект %s (%d ключей)\n", sp, n)
		emit(map[string]any{"project": sp, "keys": n})
		return 0
	}
	proj, key := resolveKeyRef(ref, fs, "sec rm <proj>/<KEY>")
	mustSecret(st, proj, key)
	if refs := st.Referrers(proj + "/" + key); len(refs) > 0 {
		warnf("ВНИМАНИЕ: на %s/%s ссылаются %s — после удаления ссылки станут битыми (перецелить: sec link …; отвязать: sec unlink …)", proj, key, strings.Join(refs, ", "))
	}
	delete(st.Projects[proj], key)
	st.Prune(proj)
	if err := store.Save(st, mkey); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record("rm", proj+"/"+key, "")
	fmt.Fprintf(stdout, "удалён %s/%s\n", proj, key)
	emit(map[string]any{"ref": proj + "/" + key})
	return 0
}

// otpCommand печатает одноразовый код из сохранённого seed: TOTP (RFC 6238)
// или HOTP (RFC 4226, значение — otpauth://hotp-URI). Код живёт секунды /
// одно использование, поэтому показывать его безопасно даже в чате.
func otpCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := newFlagSet("otp")
	var clip bool
	fs.BoolVar(&clip, "clip", false, "скопировать код в буфер, не печатать")
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, "sec otp <proj>/<KEY>")
	st, _, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	sec, _, _, ok := st.Lookup(proj, key)
	if !ok {
		dieNotFound("нет %s/%s", proj, key)
	}
	if totp.IsHOTP(sec.Value) {
		return hotpAdvance(proj, key, clip)
	}
	code, remain, err := totp.Code(sec.Value, time.Now())
	if err != nil {
		die("%s/%s: %v", proj, key, err)
	}
	audit.Record("otp", proj+"/"+key, "")
	if clip {
		if err := clipboardWrite(code); err != nil {
			dieK(kindIO, "буфер обмена: %v", err)
		}
		fmt.Fprintf(stdout, "код в буфере обмена (действителен ещё %d с)\n", remain)
		emit(map[string]any{"ref": proj + "/" + key, "clipboard": true, "remaining": remain})
		return 0
	}
	fmt.Fprintf(stdout, "%s  (действителен ещё %d с)\n", code, remain)
	emit(map[string]any{"ref": proj + "/" + key, "code": code, "remaining": remain})
	return 0
}

// hotpAdvance выдаёт HOTP-код и сдвигает счётчик в сторе. Счётчик одноразовый,
// поэтому чтение, инкремент и запись идут одной операцией под блокировкой.
// Инкремент пишется по адресу настоящего значения (у ссылки/наследования —
// в родителе: источник счётчика один) и не трогает историю/UpdatedAt —
// это расход кода, а не ротация секрета.
func hotpAdvance(proj, key string, clip bool) int {
	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	sec, _, source, ok := st.Lookup(proj, key)
	if !ok {
		dieNotFound("нет %s/%s", proj, key)
	}
	code, next, counter, err := totp.HOTPCode(sec.Value)
	if err != nil {
		die("%s/%s: %v", proj, key, err)
	}
	tp, tk := proj, key
	if source != "" {
		if p, k, good := store.SplitRef(source); good {
			tp, tk = p, k
		}
	}
	cur := st.Projects[tp][tk]
	cur.Value = next
	st.Projects[tp][tk] = cur
	if err := store.Save(st, mkey); err != nil {
		// код уже посчитан — не выдать его из-за read-only стора (бэкап 0400,
		// синхронизированная реплика) значит отказать в 2FA на ровном месте.
		// Предупреждаем: счётчик не сдвинут, повторный вызов даст тот же код.
		warnf("счётчик HOTP не сохранён (%v) — код ниже, но повторный вызов выдаст его же", err)
	}
	audit.Record("otp", proj+"/"+key, fmt.Sprintf("hotp counter=%d", counter))
	if clip {
		cerr := clipboardWrite(code)
		if cerr == nil {
			fmt.Fprintf(stdout, "HOTP-код в буфере обмена (счётчик %d использован, код одноразовый)\n", counter)
			emit(map[string]any{"ref": proj + "/" + key, "hotp": true, "counter": counter, "clipboard": true})
			return 0
		}
		// счётчик уже сдвинут и сохранён — умереть, не показав код, значит
		// рассинхронизировать строгий HOTP-сервер. Код одноразовый и уже
		// потреблён локально, печать — безопасный fallback.
		warnf("буфер обмена недоступен (%v) — счётчик уже потрачен, печатаю код:", cerr)
	}
	fmt.Fprintf(stdout, "%s  (HOTP, счётчик %d использован — код одноразовый)\n", code, counter)
	emit(map[string]any{"ref": proj + "/" + key, "hotp": true, "counter": counter, "code": code})
	return 0
}
