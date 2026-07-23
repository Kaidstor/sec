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
	"github.com/kaidstor/sec/internal/store"
)

// diffCommand сравнивает два проекта по ключам и отпечаткам — какие ключи
// совпадают по значению, различаются или есть только в одном. Значения не
// раскрываются. Удобно свериться «staging == prod» без утечки.
func diffCommand(args []string) int {
	// -e может стоять после позиционных аргументов (sec diff svc -e a b), поэтому
	// собираем позиционные и флаги в любом порядке.
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	getEnv := addEnvFlag(fs)
	pos := collectPositionals(fs, args)
	env := getEnv()
	var pa, pb string
	switch {
	case env != "" && len(pos) == 2:
		// sec diff <service> -e <envA> <envB> — два инстанса одного сервиса
		pa = resolveProj(pos[0], env)
		pb = resolveProj(pos[0], pos[1])
	case len(pos) == 2:
		pa, pb = pos[0], pos[1]
	default:
		die("нужно два проекта: sec diff <projA> <projB>  (или sec diff <service> -e <env1> <env2>)")
	}
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

// verifyCommand сверяет переданное значение с сохранённым, не раскрывая ни то,
// ни другое: отвечает только «совпадает / не совпадает». Кандидат берётся из
// скрытого ввода (по умолчанию), stdin или буфера обмена.
func verifyCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var fromClip, fromStdin bool
	fs.BoolVar(&fromClip, "clipboard", false, "взять кандидата из буфера обмена")
	fs.BoolVar(&fromStdin, "stdin", false, "взять кандидата из stdin")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec verify <proj>/<KEY>")

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
