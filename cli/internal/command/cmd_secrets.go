package command

// Команды над отдельными ключами: set / gen / get / history / undo / mv / rm / otp.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/store"
	"github.com/kaidstor/sec/internal/totp"

	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
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
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	var fromClip, clearClip, fromStdin, override bool
	var note, kind, fromFile string
	fs.BoolVar(&fromClip, "clipboard", false, "взять значение из буфера обмена")
	fs.BoolVar(&clearClip, "clear", false, "очистить буфер после сохранения (с --clipboard)")
	fs.BoolVar(&fromStdin, "stdin", false, "читать значение из stdin")
	fs.StringVar(&fromFile, "from-file", "", "взять значение из файла как есть (сертификат/ключ; бинарные — в base64)")
	fs.BoolVar(&override, "override", false, "перебить ссылку/наследование собственным значением")
	fs.StringVar(&note, "note", "", "описание/назначение ключа (метаданные, без секрета)")
	fs.StringVar(&kind, "kind", "", "тип: password|apikey|totp|file|env|...")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec set <proj>/<KEY> (или просто <KEY> внутри папки проекта)")

	// ссылку/наследование не редактируем — предупреждаем до ввода, чтобы не тратить набор впустую
	if st0, _, _, err := store.Open(false); err == nil {
		mustEditable(st0, proj, key, override)
	}

	var val, enc, fileName string
	var err error
	src := "скрытый ввод"
	switch {
	case fromFile != "":
		if fromClip || fromStdin {
			die("--from-file несовместим с --clipboard/--stdin")
		}
		fi, serr := os.Stat(fromFile)
		if serr != nil {
			die("чтение %s: %v", fromFile, serr)
		}
		if fi.Size() > maxFileSecret {
			die("%s: %d байт — больше предела %d МиБ (стор целиком живёт в памяти и истории)",
				fromFile, fi.Size(), maxFileSecret>>20)
		}
		data, rerr := os.ReadFile(fromFile)
		if rerr != nil {
			die("чтение %s: %v", fromFile, rerr)
		}
		if len(data) == 0 {
			die("файл %s пуст, ничего не сохранено", fromFile)
		}
		fileName = filepath.Base(fromFile)
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
			die("буфер обмена: %v", err)
		}
	case fromStdin || stdinPiped():
		src = "stdin"
		data, rerr := io.ReadAll(os.Stdin)
		if rerr != nil {
			die("stdin: %v", rerr)
		}
		val = string(data)
	default:
		val, err = readHidden(fmt.Sprintf("значение %s/%s: ", proj, key))
		if err != nil {
			die("%v", err)
		}
		again, aerr := readHidden("повтори: ")
		if aerr != nil {
			die("%v", aerr)
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
		die("%v", err)
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
		applyFileMeta(keys, key, fileName)
	}
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record("set", proj+"/"+key, src)
	verb := "сохранён"
	if existed {
		verb = "обновлён (прежнее значение в истории — sec undo вернёт)"
	}
	size := fmt.Sprintf("%d символов", len(val))
	if enc == store.EncB64 {
		raw, _ := (store.Secret{Value: val, Enc: enc}).Bytes()
		size = fmt.Sprintf("бинарный файл, %d байт → base64", len(raw))
	}
	fmt.Printf("%s/%s %s (%s, значение скрыто)\n", proj, key, verb, size)
	if fromClip && clearClip {
		if err := clipboardWrite(""); err == nil {
			fmt.Println("буфер обмена очищен")
		}
	}
	return 0
}

// isBinaryData — байты не годятся как текстовое значение (не-UTF-8 или NUL) —
// хранить только как base64.
func isBinaryData(data []byte) bool {
	return !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0
}

// applyFileMeta помечает ключ файловым: имя исходного файла (для get --out в
// каталог) и kind=file, если тип не задан явно.
func applyFileMeta(keys map[string]store.Secret, key, fileName string) {
	e := keys[key]
	m := store.Meta{}
	if e.Meta != nil {
		m = *e.Meta
	}
	if m.Kind == "" {
		m.Kind = "file"
	}
	m.Filename = fileName
	e.Meta = &m
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
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	var length int
	var symbols, clip, override bool
	var note, kind string
	fs.IntVar(&length, "len", 32, "длина значения")
	fs.BoolVar(&symbols, "symbols", false, "добавить спецсимволы к буквам/цифрам")
	fs.BoolVar(&clip, "clip", false, "скопировать значение в буфер обмена")
	fs.BoolVar(&override, "override", false, "перебить ссылку/наследование собственным значением")
	fs.StringVar(&note, "note", "", "описание/назначение ключа (метаданные, без секрета)")
	fs.StringVar(&kind, "kind", "", "тип: password|apikey|totp|env|...")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec gen <proj>/<KEY> [--len 32]")
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
			die("rand: %v", err)
		}
		val[i] = charset[n.Int64()]
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(true)
	if err != nil {
		die("%v", err)
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
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record("gen", proj+"/"+key, fmt.Sprintf("len=%d", length))
	verb := "сгенерирован и сохранён"
	if existed {
		verb = "перегенерирован (прежнее значение в истории — sec undo вернёт)"
	}
	fmt.Printf("%s/%s %s (%d символов, значение скрыто)\n", proj, key, verb, length)
	if clip {
		if err := clipboardWrite(string(val)); err != nil {
			die("буфер обмена: %v", err)
		}
		fmt.Println("значение в буфере обмена — вставь куда нужно")
	}
	return 0
}

func getCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	var clip, peek, fp, once bool
	var prevN int
	fs.BoolVar(&clip, "clip", false, "скопировать в буфер обмена, не печатать")
	fs.BoolVar(&peek, "peek", false, "показать маску ab…yz и длину вместо значения")
	fs.BoolVar(&fp, "fingerprint", false, "показать отпечаток fp:… (безопасно для чата)")
	fs.BoolVar(&once, "once", false, "показать значение и сразу удалить ключ (одноразовая передача)")
	var clearAfter, outFile string
	fs.StringVar(&clearAfter, "clear-after", "", "с --clip: очистить буфер через интервал (напр. 20s), если не перезаписан")
	fs.StringVar(&outFile, "out", "", "записать значение в файл 0600 (единственный способ достать бинарные)")
	fs.IntVar(&prevN, "prev", 0, "показать N-е предыдущее значение (1 = прошлое)")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec get <proj>/<KEY>")

	st, mkey, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	sec, org, source, ok := st.Lookup(proj, key)
	if !ok {
		if org == store.OriginRef {
			die("%s/%s ссылается на %s, но значения по цепочке нет (родитель удалён?)", proj, key, source)
		}
		die("нет %s/%s (смотри: sec ls %s)", proj, key, proj)
	}
	val, enc := sec.Value, sec.Enc
	detail := "показано"
	if prevN > 0 {
		if prevN > len(sec.History) {
			die("у %s/%s в истории только %d значений (sec history %s)", proj, key, len(sec.History), ref)
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
			die("%s/%s: %v", proj, key, berr)
		}
		target := outFile
		if fi, serr := os.Stat(outFile); serr == nil && fi.IsDir() {
			name := key // в каталог — под исходным именем файла, если оно известно
			if sec.Meta != nil && sec.Meta.Filename != "" {
				name = sec.Meta.Filename
			}
			target = filepath.Join(outFile, name)
		}
		if werr := writeFile0600(target, raw); werr != nil {
			die("запись %s: %v", target, werr)
		}
		audit.Record("get", proj+"/"+key, strings.Replace(detail, "показано", "→ файл "+target, 1))
		fmt.Printf("записан %s (0600, %d байт) — файл вне шифрованного стора, не коммить\n", target, len(raw))
		return 0
	}
	isBin := enc == store.EncB64
	if fp {
		audit.Record("get", proj+"/"+key, "отпечаток")
		fmt.Println(store.Fingerprint(mkey, val))
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
			die("%s/%s не собственное значение (%s) — --once уничтожил бы ссылку, а значение осталось бы в родителе", proj, key, source)
		}
		unlock := store.Lock()
		defer unlock()
		st2, mkey2, _, err := store.Open(false)
		if err != nil {
			die("%v", err)
		}
		if _, ok := st2.Projects[proj][key]; !ok {
			die("нет %s/%s", proj, key)
		}
		if refs := st2.Referrers(proj + "/" + key); len(refs) > 0 {
			fmt.Fprintf(os.Stderr, "sec: ВНИМАНИЕ: на %s/%s ссылаются %s — после --once удаления ссылки станут битыми\n", proj, key, strings.Join(refs, ", "))
		}
		// буфер — до удаления: если он недоступен, ключ остаётся в сторе,
		// иначе значение потерялось бы безвозвратно
		if clip {
			if err := clipboardWrite(val); err != nil {
				die("буфер обмена: %v (ключ не удалён)", err)
			}
		}
		delete(st2.Projects[proj], key)
		st2.Prune(proj)
		if err := store.Save(st2, mkey2); err != nil {
			die("запись хранилища: %v", err)
		}
		if clip {
			audit.Record("get", proj+"/"+key, "once (в буфер и удалено)")
			fmt.Println("скопировано в буфер обмена (значение не показано)")
		} else {
			audit.Record("get", proj+"/"+key, "once (показано и удалено)")
			fmt.Println(val)
		}
		fmt.Fprintf(os.Stderr, "sec: %s/%s удалён после одноразового показа\n", proj, key)
		return 0
	}
	if peek {
		audit.Record("get", proj+"/"+key, strings.Replace(detail, "показано", "маска", 1))
		if isBin {
			raw, _ := (store.Secret{Value: val, Enc: enc}).Bytes()
			fmt.Printf("%s (бинарный файл, %d байт — sec get %s --out <файл>)\n", store.MaskValue(val), len(raw), ref)
			return 0
		}
		fmt.Printf("%s (%d символов)\n", store.MaskValue(val), len([]rune(val)))
		return 0
	}
	if clip {
		if isBin {
			die("%s/%s — бинарный (файловый) секрет, в буфер обмена не копируется: sec get %s --out <файл>", proj, key, ref)
		}
		if err := clipboardWrite(val); err != nil {
			die("буфер обмена: %v", err)
		}
		msg := "скопировано в буфер обмена (значение не показано)"
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
				fmt.Fprintf(os.Stderr, "sec: авто-очистка буфера не запущена: %v\n", err)
			} else {
				msg += "; очистится через " + clearAfter + ", если не перезапишешь"
			}
		}
		audit.Record("get", proj+"/"+key, strings.Replace(detail, "показано", "в буфер", 1))
		fmt.Println(msg)
		return 0
	}
	if isBin {
		die("%s/%s — бинарный (файловый) секрет, сырые байты в терминал не печатаются: sec get %s --out <файл>", proj, key, ref)
	}
	audit.Record("get", proj+"/"+key, detail)
	fmt.Println(val)
	return 0
}

// historyCommand показывает версии значения маскированно (peek + длина + дата).
func historyCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "машинный вывод с отпечатками (без значений)")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec history <proj>/<KEY>")
	st, mkey, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	sec, org, source, ok := st.Lookup(proj, key)
	if !ok {
		die("нет %s/%s", proj, key)
	}
	if org != store.OriginOwn && !asJSON {
		fmt.Printf("%s/%s — значение из %s (по ссылке/наследованию), история ниже — родителя\n", proj, key, source)
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
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return 0
	}
	fmt.Printf("%s/%s — версий: %d\n", proj, key, 1+len(sec.History)+len(sec.RedoStack))
	// «будущее» (отменённое через undo) — сверху, самое дальнее первым.
	for i := len(sec.RedoStack) - 1; i >= 0; i-- {
		v := sec.RedoStack[i]
		fmt.Printf("  %+3d  %-8s %4d симв.  %s  (отменено, sec redo вернёт)\n",
			i+1, store.MaskValue(v.Value), len([]rune(v.Value)), fmtTime(v.UpdatedAt))
	}
	fmt.Printf("  тек  %-8s %4d симв.  %s\n", store.MaskValue(sec.Value), len([]rune(sec.Value)), fmtTime(sec.UpdatedAt))
	for i, v := range sec.History {
		fmt.Printf("  %3d  %-8s %4d симв.  %s\n", -(i + 1), store.MaskValue(v.Value), len([]rune(v.Value)), fmtTime(v.UpdatedAt))
	}
	return 0
}

// undoCommand шагает на одну версию назад: History[0] становится текущим,
// вытесненное текущее уходит в redo-стек. Повторный undo идёт глубже в прошлое
// и упирается в стену, когда история кончилась; sec redo возвращает вперёд.
func undoCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("undo", flag.ExitOnError)
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec undo <proj>/<KEY>")
	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	mustEditable(st, proj, key, false) // у ссылки/наследования своей истории нет — она у родителя
	next, ok := mustSecret(st, proj, key).Undo()
	if !ok {
		die("у %s/%s нет более старых версий (sec history %s)", proj, key, ref)
	}
	st.Projects[proj][key] = next
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record("undo", proj+"/"+key, "")
	fmt.Printf("%s/%s ← версия от %s (%d символов); ещё старше: %d, вернуть вперёд: sec redo\n",
		proj, key, fmtTime(next.UpdatedAt), len([]rune(next.Value)), len(next.History))
	return 0
}

// redoCommand — обратная к undo: возвращает ближайшее отменённое значение.
func redoCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("redo", flag.ExitOnError)
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec redo <proj>/<KEY>")
	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	mustEditable(st, proj, key, false)
	next, ok := mustSecret(st, proj, key).Redo()
	if !ok {
		die("у %s/%s нет отменённых значений впереди (redo нечего возвращать)", proj, key)
	}
	st.Projects[proj][key] = next
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record("redo", proj+"/"+key, "")
	fmt.Printf("%s/%s → версия от %s (%d символов); ещё впереди: %d\n",
		proj, key, fmtTime(next.UpdatedAt), len([]rune(next.Value)), len(next.RedoStack))
	return 0
}

// forgetCommand вычищает историю и redo ключа, оставляя текущее значение.
// Нужен после ротации скомпрометированного секрета: обычный set утаскивает
// старое (утёкшее) значение в историю — forget убирает его из хранилища.
func forgetCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("forget", flag.ExitOnError)
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec forget <proj>/<KEY>")
	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	mustEditable(st, proj, key, false)
	cur := mustSecret(st, proj, key)
	n := len(cur.History) + len(cur.RedoStack)
	if n == 0 {
		fmt.Printf("%s/%s: прошлых версий нет, чистить нечего\n", proj, key)
		return 0
	}
	st.Projects[proj][key] = cur.Forget()
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record("forget", proj+"/"+key, fmt.Sprintf("удалено версий: %d", n))
	fmt.Printf("%s/%s: удалено прошлых версий: %d (текущее значение осталось)\n", proj, key, n)
	return 0
}

// mvCommand переносит/переименовывает ключ, cpCommand копирует — вся логика
// общая (moveKey), отличается только удалением оригинала.
func mvCommand(args []string) int { return moveKey(args, true) }
func cpCommand(args []string) int { return moveKey(args, false) }

// moveKey переносит (remove=true) или копирует (remove=false) ключ без
// раскрытия значения — вместе едут история, redo и метаданные. Назначение без
// "/" — имя проекта, имя ключа сохраняется (переименование внутри проекта:
// sec mv demo/OLD demo/NEW). Инстанс (-e/.sec) берётся по источнику и
// применяется к обоим концам.
func moveKey(args []string, remove bool) int {
	name := "cp"
	if remove {
		name = "mv"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	var force bool
	fs.BoolVar(&force, "force", false, "перезаписать существующий ключ назначения")
	getEnv := addEnvFlag(fs)
	pos := collectPositionals(fs, args)
	if len(pos) != 2 {
		die("нужно два аргумента: sec %s <proj>/<KEY> <proj2>[/<KEY2>]", name)
	}
	env := resolvedEnv(getEnv(), refService(pos[0]))
	sp, sk := resolveRef(pos[0], env)
	var dp, dk string
	if strings.Contains(pos[1], "/") {
		dp, dk = resolveRef(pos[1], env)
	} else {
		if !projRe.MatchString(pos[1]) {
			die("некорректное имя проекта %q", pos[1])
		}
		dp, dk = store.ProjKey(pos[1], env), sk
	}
	if sp == dp && sk == dk {
		die("источник и назначение совпадают")
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	s := mustSecret(st, sp, sk)
	if _, busy := st.Projects[dp][dk]; busy && !force {
		die("%s/%s уже существует — sec %s --force перезапишет", dp, dk, name)
	}
	st.Project(dp)[dk] = s
	note := "копия, оригинал на месте, значение не показано"
	if remove {
		delete(st.Projects[sp], sk)
		st.Prune(sp)
		note = "история сохранена, значение не показано"
	}
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record(name, sp+"/"+sk, "→ "+dp+"/"+dk)
	fmt.Printf("%s/%s → %s/%s (%s)\n", sp, sk, dp, dk, note)
	return 0
}

func rmCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("rm", flag.ExitOnError)
	var all bool
	fs.BoolVar(&all, "all", false, "удалить проект целиком")
	getEnv := addEnvFlag(fs)
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
		die("%v", err)
	}
	if all {
		if strings.Contains(ref, "/") {
			die("--all принимает имя проекта, а не ключ: sec rm %s --all", strings.Split(ref, "/")[0])
		}
		sp := resolveProj(ref, resolvedEnv(getEnv(), ref))
		n := len(st.Projects[sp])
		if n == 0 {
			die("проекта %q нет", sp)
		}
		if refs := st.ProjectReferrers(sp); len(refs) > 0 {
			fmt.Fprintf(os.Stderr, "sec: ВНИМАНИЕ: на ключи %s ссылаются %s — после удаления ссылки станут битыми\n", sp, strings.Join(refs, ", "))
		}
		if ext := st.Extenders(sp); len(ext) > 0 {
			fmt.Fprintf(os.Stderr, "sec: ВНИМАНИЕ: от %s наследуют %s — потеряют унаследованные ключи (отвязать: sec extend <proj> --remove %s)\n", sp, strings.Join(ext, ", "), store.RefToCLIProj(sp))
		}
		delete(st.Projects, sp)
		delete(st.Extends, sp) // осиротевшие исходящие связи удаляемого проекта
		if err := store.Save(st, mkey); err != nil {
			die("запись хранилища: %v", err)
		}
		audit.Record("rm", sp, fmt.Sprintf("проект целиком (%d ключей)", n))
		fmt.Printf("удалён проект %s (%d ключей)\n", sp, n)
		return 0
	}
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec rm <proj>/<KEY>")
	mustSecret(st, proj, key)
	if refs := st.Referrers(proj + "/" + key); len(refs) > 0 {
		fmt.Fprintf(os.Stderr, "sec: ВНИМАНИЕ: на %s/%s ссылаются %s — после удаления ссылки станут битыми (перецелить: sec link …; отвязать: sec unlink …)\n", proj, key, strings.Join(refs, ", "))
	}
	delete(st.Projects[proj], key)
	st.Prune(proj)
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record("rm", proj+"/"+key, "")
	fmt.Printf("удалён %s/%s\n", proj, key)
	return 0
}

// otpCommand печатает одноразовый код из сохранённого seed: TOTP (RFC 6238)
// или HOTP (RFC 4226, значение — otpauth://hotp-URI). Код живёт секунды /
// одно использование, поэтому показывать его безопасно даже в чате.
func otpCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("otp", flag.ExitOnError)
	var clip bool
	fs.BoolVar(&clip, "clip", false, "скопировать код в буфер, не печатать")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec otp <proj>/<KEY>")
	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	sec, _, _, ok := st.Lookup(proj, key)
	if !ok {
		die("нет %s/%s", proj, key)
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
			die("буфер обмена: %v", err)
		}
		fmt.Printf("код в буфере обмена (действителен ещё %d с)\n", remain)
		return 0
	}
	fmt.Printf("%s  (действителен ещё %d с)\n", code, remain)
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
		die("%v", err)
	}
	sec, _, source, ok := st.Lookup(proj, key)
	if !ok {
		die("нет %s/%s", proj, key)
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
		die("запись хранилища: %v", err)
	}
	audit.Record("otp", proj+"/"+key, fmt.Sprintf("hotp counter=%d", counter))
	if clip {
		cerr := clipboardWrite(code)
		if cerr == nil {
			fmt.Printf("HOTP-код в буфере обмена (счётчик %d использован, код одноразовый)\n", counter)
			return 0
		}
		// счётчик уже сдвинут и сохранён — умереть, не показав код, значит
		// рассинхронизировать строгий HOTP-сервер. Код одноразовый и уже
		// потреблён локально, печать — безопасный fallback.
		fmt.Fprintf(os.Stderr, "sec: буфер обмена недоступен (%v) — счётчик уже потрачен, печатаю код:\n", cerr)
	}
	fmt.Printf("%s  (HOTP, счётчик %d использован — код одноразовый)\n", code, counter)
	return 0
}
