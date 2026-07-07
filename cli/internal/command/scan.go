package command

// Скан на утечку: ищет сохранённые значения секретов в файлах/тексте/диффе,
// чтобы поймать секрет до того, как он уедет в git-коммит, лог или чат.
// Печатает только место находки и имя ключа — само значение никогда.
// Ненулевой код при находках делает его пригодным как pre-commit хук / CI-гейт.
//
//	sec scan path/ file.env         просканировать файлы и каталоги
//	sec scan -                      просканировать stdin
//	sec scan --staged               просканировать git diff --cached (добавленные строки)

import (
	"github.com/kaidstor/sec/internal/store"

	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const scanMaxFileBytes = 8 << 20 // не читаем файлы крупнее 8 МБ

type leak struct {
	loc  string // path:line или "stdin:line"
	refs []string
}

// collectStoreValues собирает карту «значение → ключи, которым оно принадлежит»
// из всех собственных секретов стора (ссылки пропускаются — значение у родителя,
// там и ищется). Значения короче minLen отбрасываются как шум (их число —
// второй результат). При withHistory включаются и прошлые значения из истории
// (ref получает суффикс ~prev). Общий сбор для scan (поиск утечек) и redact
// (чистка текста).
func collectStoreValues(st *store.Store, minLen int, withHistory bool) (map[string][]string, int) {
	values := map[string][]string{}
	skipped := 0
	add := func(val, ref string) {
		if len([]rune(val)) < minLen {
			skipped++
			return
		}
		values[val] = append(values[val], ref)
	}
	for _, p := range store.SortedKeys(st.Projects) {
		for _, k := range store.SortedKeys(st.Projects[p]) {
			sec := st.Projects[p][k]
			if sec.Ref != "" {
				continue
			}
			ref := p + "/" + k
			add(sec.Value, ref)
			if withHistory {
				for _, v := range sec.History {
					add(v.Value, ref+"~prev")
				}
			}
		}
	}
	return values, skipped
}

func scanCommand(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var staged bool
	var minLen int
	var withHistory bool
	fs.BoolVar(&staged, "staged", false, "сканировать git diff --cached (добавленные строки)")
	fs.IntVar(&minLen, "min", 8, "игнорировать значения короче N символов (шум)")
	fs.BoolVar(&withHistory, "history", false, "искать и прошлые значения из истории, не только текущие")
	_ = fs.Parse(args)
	paths := fs.Args()

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}

	values, skipped := collectStoreValues(st, minLen, withHistory)
	if len(values) == 0 {
		fmt.Fprintln(os.Stderr, "sec: нет значений для поиска (все короче --min либо стор пуст)")
		return 0
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "sec: пропущено значений короче %d символов: %d (искать всё: --min 1)\n", minLen, skipped)
	}

	var leaks []leak

	switch {
	case staged:
		leaks = scanStaged(values)
	case len(paths) == 1 && paths[0] == "-":
		leaks = scanReader("stdin", os.Stdin, values)
	case len(paths) == 0:
		die("укажи пути, - для stdin или --staged")
	default:
		self := store.Path()
		for _, root := range paths {
			filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					fmt.Fprintf(os.Stderr, "sec: %s: %v\n", path, err)
					return nil
				}
				if d.IsDir() {
					if d.Name() == ".git" || d.Name() == "node_modules" {
						return filepath.SkipDir
					}
					return nil
				}
				if path == self || strings.HasPrefix(filepath.Base(path), "audit.jsonl") {
					return nil
				}
				leaks = append(leaks, scanFile(path, values)...)
				return nil
			})
		}
	}

	if len(leaks) == 0 {
		fmt.Println("утечек не найдено")
		return 0
	}
	for _, l := range leaks {
		fmt.Printf("%s: %s\n", l.loc, strings.Join(dedupe(l.refs), ", "))
	}
	fmt.Fprintf(os.Stderr, "sec: найдены значения секретов в открытом виде — не коммить/не публикуй\n")
	return 1
}

func scanFile(path string, values map[string][]string) []leak {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > scanMaxFileBytes {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := f.Read(head)
	if bytes.IndexByte(head[:n], 0) >= 0 {
		return nil // бинарник
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil
	}
	return scanReader(path, f, values)
}

// matchValues возвращает refs всех сохранённых значений, встречающихся в строке.
func matchValues(text string, values map[string][]string) []string {
	var hits []string
	for val, refs := range values {
		if strings.Contains(text, val) {
			hits = append(hits, refs...)
		}
	}
	return hits
}

func scanReader(name string, r io.Reader, values map[string][]string) []leak {
	var out []leak
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	line := 0
	for sc.Scan() {
		line++
		if hits := matchValues(sc.Text(), values); len(hits) > 0 {
			out = append(out, leak{fmt.Sprintf("%s:%d", name, line), hits})
		}
	}
	return out
}

// scanStaged сканирует добавленные строки из индекса git (то, что вот-вот
// уедет в коммит). Разбирает `git diff --cached -U0` по хедерам файлов.
func scanStaged(values map[string][]string) []leak {
	out, err := exec.Command("git", "diff", "--cached", "-U0").Output()
	if err != nil {
		die("git diff --cached: %v (это git-репозиторий?)", err)
	}
	var leaks []leak
	file, line := "", 0
	for _, raw := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(raw, "+++ b/"):
			file = strings.TrimPrefix(raw, "+++ b/")
		case strings.HasPrefix(raw, "@@"):
			// @@ -a,b +c,d @@ — берём стартовую строку нового файла
			if i := strings.Index(raw, "+"); i >= 0 {
				num := raw[i+1:]
				if j := strings.IndexAny(num, ", "); j >= 0 {
					num = num[:j]
				}
				fmt.Sscanf(num, "%d", &line)
			}
		case strings.HasPrefix(raw, "+") && !strings.HasPrefix(raw, "+++"):
			if hits := matchValues(raw[1:], values); len(hits) > 0 {
				leaks = append(leaks, leak{fmt.Sprintf("%s:%d", file, line), hits})
			}
			line++
		}
	}
	return leaks
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
