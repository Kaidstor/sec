package command

// Команды diff/verify сравнивают/сверяют секреты по отпечаткам, не раскрывая
// значений. Сам отпечаток (HMAC-SHA256 под мастер-ключом) — store.Fingerprint.

import (
	"crypto/hmac"
	"crypto/subtle"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/dotenv"
	"github.com/kaidstor/sec/internal/store"
)

// diffCommand сравнивает два проекта по ключам и отпечаткам — какие ключи
// совпадают по значению, различаются или есть только в одном. Значения не
// раскрываются. Удобно свериться «staging == prod» без утечки:
// sec diff bot@commercial bot@max. Второй аргумент может быть и env-файлом
// ([user@]host:/путь или локальный путь) — тогда стор сверяется с ним
// (см. diffAgainstFile).
func diffCommand(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	var sudo bool
	var only string
	fs.BoolVar(&sudo, "sudo", false, "читать файл на хосте под sudo (root-овые прод-конфиги)")
	fs.StringVar(&only, "only", "", "сверять только перечисленные ключи (через запятую)")
	pos := collectPositionals(fs, args)

	// Файловый режим проверяем первым; цена — файл в текущей папке, названный
	// ровно как проект, победит проект (та же неоднозначность, что у sec import).
	if len(pos) == 2 && looksLikeEnvTarget(pos[1]) {
		return diffAgainstFile(pos[0], pos[1], only, sudo)
	}
	if only != "" || sudo {
		die("--only/--sudo работают только при сверке с env-файлом: sec diff <proj> <host>:/путь")
	}

	if len(pos) != 2 {
		die("нужно два проекта: sec diff <projA> <projB>  (профили — в адресе: sec diff <svc>@<prof1> <svc>@<prof2>)")
	}
	pa, pb := resolveProj(pos[0]), resolveProj(pos[1])
	st, mkey, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	a, b := st.EffectiveKeys(pa), st.EffectiveKeys(pb) // ссылки/наследование сравниваем по эффективным значениям
	if len(a) == 0 {
		die("проект %q пуст или не существует", pa)
	}
	if len(b) == 0 {
		die("проект %q пуст или не существует", pb)
	}

	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	same, differ, onlyA, onlyB := 0, 0, 0, 0
	for _, k := range store.SortedKeys(seen) {
		sa, okA := a[k]
		sb, okB := b[k]
		switch {
		case okA && okB:
			if hmac.Equal([]byte(store.Fingerprint(mkey, sa.Value)), []byte(store.Fingerprint(mkey, sb.Value))) {
				fmt.Printf("%-32s = совпадают\n", k)
				same++
			} else {
				fmt.Printf("%-32s ≠ различаются\n", k)
				differ++
			}
		case okA:
			fmt.Printf("%-32s < только в %s\n", k, pa)
			onlyA++
		default:
			fmt.Printf("%-32s > только в %s\n", k, pb)
			onlyB++
		}
	}
	fmt.Printf("итого: совпадают %d, различаются %d, только в %s — %d, только в %s — %d\n",
		same, differ, pa, onlyA, pb, onlyB)
	if differ > 0 || onlyA > 0 || onlyB > 0 {
		return 2
	}
	return 0
}

// diffAgainstFile сверяет проект с env-файлом — локальным или на хосте по ssh.
// Только чтение: ничего не пишет ни в стор, ни в файл. Значения не
// раскрываются, кроме ключей kind: config (см. envdiff.go).
func diffAgainstFile(service, target, only string, sudo bool) int {
	t, err := parseEnvTarget(target)
	if err != nil {
		die("%v", err)
	}
	proj := resolveProj(service)

	st, mkey, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	keys := envKeysOf(st, proj, only)

	data, exists, err := t.read(sudo)
	if err != nil {
		die("чтение %s: %v", t, err)
	}
	if !exists {
		die("%s: файла нет (проверь путь; sudo для root-овых каталогов — --sudo)", t)
	}
	if ml := dotenv.MultilineKeys(string(data)); len(ml) > 0 {
		fmt.Fprintf(os.Stderr, "sec: в %s многострочные значения (%s) — сверка по ним неверна, а sec deploy на таком файле откажется работать\n",
			t, strings.Join(ml, ", "))
	}
	fileKV := parseEnvTargetFile(t, data)
	if only != "" { // иначе каждый несравниваемый ключ файла попал бы в «только на хосте»
		for k := range fileKV {
			if _, ok := keys[k]; !ok {
				delete(fileKV, k)
			}
		}
	}

	c := printEnvDiff(compareEnvFile(keys, fileKV, mkey), t, false)
	audit.Record("diff", proj, "↔ "+t.String())
	// Ненулевой код — только на то, что применил бы deploy. Ключи, которых нет в
	// сторе, для прод-конфига норма (их патчит CI), и падать на них значило бы
	// сделать команду непригодной как гейт.
	if c.changed() {
		return 2
	}
	return 0
}

// parseEnvTargetFile разбирает содержимое цели, отправляя предупреждения парсера
// в stderr с указанием, чей это файл.
func parseEnvTargetFile(t envTarget, data []byte) map[string]string {
	kv, warns := dotenv.Parse(string(data))
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "sec: %s: %s\n", t, w)
	}
	return kv
}

// verifyCommand сверяет переданное значение с сохранённым, не раскрывая ни то,
// ни другое: отвечает только «совпадает / не совпадает». Кандидат берётся из
// скрытого ввода (по умолчанию), stdin или буфера обмена.
func verifyCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var fromClip, fromStdin bool
	fs.BoolVar(&fromClip, "clipboard", false, "взять кандидата из буфера обмена")
	fs.BoolVar(&fromStdin, "stdin", false, "взять кандидата из stdin")
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, "sec verify <proj>/<KEY>")

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	sec, _, _, ok := st.Lookup(proj, key)
	if !ok {
		die("нет %s/%s", proj, key)
	}

	var cand string
	switch {
	case fromClip:
		cand, err = clipboardRead()
		if err != nil {
			die("буфер обмена: %v", err)
		}
	case fromStdin || stdinPiped():
		data, rerr := io.ReadAll(os.Stdin)
		if rerr != nil {
			die("stdin: %v", rerr)
		}
		cand = string(data)
	default:
		cand, err = readHidden(fmt.Sprintf("значение для сверки с %s/%s: ", proj, key))
		if err != nil {
			die("%v", err)
		}
	}
	// сверяем с сырыми байтами значения: у бинарных Value — base64, сравнивать
	// нужно декодированное, и только байт-в-байт. Текстовым прощаем хвостовой
	// перевод строки с обеих сторон: файловые секреты хранятся без трима
	// (cat добавляет \n кандидату), обычные тримятся при set.
	stored, berr := sec.Bytes()
	if berr != nil {
		die("%s/%s: %v", proj, key, berr)
	}

	audit.Record("verify", proj+"/"+key, "")
	match := subtle.ConstantTimeCompare([]byte(cand), stored) == 1
	if !match && !sec.IsBinary() {
		match = subtle.ConstantTimeCompare(
			[]byte(strings.TrimRight(cand, "\r\n")),
			[]byte(strings.TrimRight(sec.Value, "\r\n"))) == 1
	}
	if match {
		fmt.Println("совпадает")
		return 0
	}
	fmt.Println("НЕ совпадает")
	return 1
}
