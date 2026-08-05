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

// storeScope — что из стора берут в поиск scan и redact.
type storeScope struct {
	minLen        int
	withHistory   bool
	includeConfig bool // ключи kind: config — по умолчанию не ищем (это не секреты)
}

// scanSkips — что и почему не попало в поиск (для сообщений в stderr).
type scanSkips struct{ short, config int }

// collectStoreValues собирает карту «значение → ключи, которым оно принадлежит»
// из всех собственных секретов стора (ссылки пропускаются — значение у родителя,
// там и ищется). Значения короче minLen отбрасываются как шум, значения
// kind: config — как несекретные (это настройки: endpoint, размер кэша). При
// withHistory включаются и прошлые значения из истории (ref получает суффикс
// ~prev). Общий сбор для scan (поиск утечек) и redact (чистка текста).
func collectStoreValues(st *store.Store, sc storeScope) (map[string][]string, scanSkips) {
	values := map[string][]string{}
	var skips scanSkips
	add := func(val, ref string) {
		if len([]rune(val)) < sc.minLen {
			skips.short++
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
			if sec.IsConfig() && !sc.includeConfig {
				skips.config++
				continue
			}
			ref := p + "/" + k
			add(sec.Value, ref)
			if sc.withHistory {
				for _, v := range sec.History {
					add(v.Value, ref+"~prev")
				}
			}
		}
	}
	return values, skips
}

// reportScanSkips печатает, что осталось за бортом поиска, и как это вернуть.
func reportScanSkips(skips scanSkips, minLen int) {
	if skips.short > 0 {
		fmt.Fprintf(os.Stderr, "sec: пропущено значений короче %d символов: %d (искать всё: --min 1)\n", minLen, skips.short)
	}
	if skips.config > 0 {
		fmt.Fprintf(os.Stderr, "sec: пропущено несекретных значений (kind: config): %d (искать и их: --include-config)\n", skips.config)
	}
}

// collectBinaryValues — сырые байты бинарных (base64) секретов, ключ карты —
// байты как string. Утёкший на диск файл в исходной форме base64-текста не
// содержит — искать надо сами байты, текстовый скан их не увидит.
func collectBinaryValues(st *store.Store, sc storeScope) map[string][]string {
	bins := map[string][]string{}
	add := func(v store.Version, ref string) {
		if v.Enc != store.EncB64 {
			return
		}
		raw, err := (store.Secret{Value: v.Value, Enc: v.Enc}).Bytes()
		if err != nil || len(raw) < sc.minLen {
			return
		}
		bins[string(raw)] = append(bins[string(raw)], ref)
	}
	for _, p := range store.SortedKeys(st.Projects) {
		for _, k := range store.SortedKeys(st.Projects[p]) {
			sec := st.Projects[p][k]
			if sec.Ref != "" {
				continue
			}
			if sec.IsConfig() && !sc.includeConfig {
				continue
			}
			ref := p + "/" + k
			add(store.Version{Value: sec.Value, Enc: sec.Enc}, ref)
			if sc.withHistory {
				for _, v := range sec.History {
					add(v, ref+"~prev")
				}
			}
		}
	}
	return bins
}

func scanCommand(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var staged bool
	var minLen int
	var withHistory, includeConfig bool
	fs.BoolVar(&staged, "staged", false, "сканировать git diff --cached (добавленные строки)")
	fs.IntVar(&minLen, "min", 8, "игнорировать значения короче N символов (шум)")
	fs.BoolVar(&withHistory, "history", false, "искать и прошлые значения из истории, не только текущие")
	fs.BoolVar(&includeConfig, "include-config", false, "искать и несекретные значения kind: config")
	// collectPositionals — чтобы флаги работали и после путей (sec scan src --min 4),
	// как в redact: иначе флаг уезжает в пути и падает «lstat --min».
	paths := collectPositionals(fs, args)

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}

	scope := storeScope{minLen: minLen, withHistory: withHistory, includeConfig: includeConfig}
	values, skips := collectStoreValues(st, scope)
	bins := collectBinaryValues(st, scope)
	if len(values) == 0 && len(bins) == 0 {
		fmt.Fprintln(os.Stderr, "sec: нет значений для поиска (все короче --min либо стор пуст)")
		return 0
	}
	reportScanSkips(skips, minLen)

	var leaks []leak

	switch {
	case staged:
		leaks = append(scanStaged(values), scanStagedBinaries(bins)...)
	case len(paths) == 1 && paths[0] == "-":
		data, rerr := io.ReadAll(io.LimitReader(os.Stdin, scanMaxFileBytes))
		if rerr != nil {
			die("чтение stdin: %v", rerr)
		}
		leaks = scanData("stdin", data, values, bins)
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
				leaks = append(leaks, scanFile(path, values, bins)...)
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

func scanFile(path string, values, bins map[string][]string) []leak {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > scanMaxFileBytes {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return scanData(path, data, values, bins)
}

// scanData ищет утечки в содержимом: сырые байты бинарных секретов — по всему
// содержимому целиком (в любом файле, даже «текстовом» — бинарь мог быть вклеен
// глубже первых 512 байт), текстовые значения — построчно в текстовых файлах.
func scanData(name string, data []byte, values, bins map[string][]string) []leak {
	var out []leak
	for raw, refs := range bins {
		if bytes.Contains(data, []byte(raw)) {
			out = append(out, leak{name, refs})
		}
	}
	head := data
	if len(head) > 512 {
		head = head[:512]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return out // бинарник — построчный текстовый скан не имеет смысла
	}
	return append(out, scanReader(name, bytes.NewReader(data), values)...)
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

// splitValues делит значения на однострочные и многострочные: первые ищутся
// построчно (точный номер строки в отчёте), вторые (PEM-ключи и другие файловые
// секреты) — по тексту целиком, иначе им не совпасть ни с одной строкой.
func splitValues(values map[string][]string) (single, multi map[string][]string) {
	single, multi = map[string][]string{}, map[string][]string{}
	for v, refs := range values {
		if strings.ContainsRune(v, '\n') {
			multi[v] = refs
		} else {
			single[v] = refs
		}
	}
	return single, multi
}

// matchMulti ищет многострочные значения в тексте целиком; loc(номер строки
// начала совпадения) — адрес для отчёта. Хвостовой перевод строки значения не
// обязан совпасть (файл могли вставить без финального \n).
func matchMulti(text string, multi map[string][]string, loc func(line int) string) []leak {
	var out []leak
	for val, refs := range multi {
		v := strings.TrimRight(val, "\r\n")
		if idx := strings.Index(text, v); idx >= 0 {
			out = append(out, leak{loc(1 + strings.Count(text[:idx], "\n")), refs})
		}
	}
	return out
}

func scanReader(name string, r io.Reader, values map[string][]string) []leak {
	single, multi := splitValues(values)
	var out []leak
	var full strings.Builder // текст целиком — для многострочных значений
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	line := 0
	for sc.Scan() {
		line++
		if len(multi) > 0 {
			full.WriteString(sc.Text())
			full.WriteByte('\n')
		}
		if hits := matchValues(sc.Text(), single); len(hits) > 0 {
			out = append(out, leak{fmt.Sprintf("%s:%d", name, line), hits})
		}
	}
	out = append(out, matchMulti(full.String(), multi, func(l int) string {
		return fmt.Sprintf("%s:%d", name, l)
	})...)
	return out
}

// scanStaged сканирует добавленные строки из индекса git (то, что вот-вот
// уедет в коммит). Разбирает `git diff --cached -U0` по хедерам файлов.
// Подряд идущие добавленные строки склеиваются в блок — иначе многострочные
// (файловые) секреты не совпали бы ни с одной отдельной строкой диффа.
func scanStaged(values map[string][]string) []leak {
	out, err := exec.Command("git", "diff", "--cached", "-U0").Output()
	if err != nil {
		die("git diff --cached: %v (это git-репозиторий?)", err)
	}
	single, multi := splitValues(values)
	var leaks []leak
	file, line := "", 0
	var block []string // текущая пачка добавленных строк
	blockStart := 0
	flush := func() {
		if len(block) == 0 {
			return
		}
		f, start := file, blockStart
		leaks = append(leaks, matchMulti(strings.Join(block, "\n"), multi, func(l int) string {
			return fmt.Sprintf("%s:%d", f, start+l-1)
		})...)
		block = nil
	}
	for _, raw := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(raw, "+++ b/"):
			flush()
			file = strings.TrimPrefix(raw, "+++ b/")
		case strings.HasPrefix(raw, "@@"):
			flush()
			// @@ -a,b +c,d @@ — берём стартовую строку нового файла
			if i := strings.Index(raw, "+"); i >= 0 {
				num := raw[i+1:]
				if j := strings.IndexAny(num, ", "); j >= 0 {
					num = num[:j]
				}
				fmt.Sscanf(num, "%d", &line)
			}
		case strings.HasPrefix(raw, "+") && !strings.HasPrefix(raw, "+++"):
			if len(block) == 0 {
				blockStart = line
			}
			block = append(block, raw[1:])
			if hits := matchValues(raw[1:], single); len(hits) > 0 {
				leaks = append(leaks, leak{fmt.Sprintf("%s:%d", file, line), hits})
			}
			line++
		default:
			flush()
		}
	}
	flush()
	return leaks
}

// scanStagedBinaries ищет сырые байты бинарных секретов в застейдженных блобах:
// в тексте diff содержимого бинарных файлов нет («Binary files differ»), поэтому
// каждый застейдженный файл читается из индекса (git show :путь) и проверяется
// на вхождение целиком. Текстовые блобы проверяются тоже — бинарь могли вклеить
// в «текстовый» файл.
func scanStagedBinaries(bins map[string][]string) []leak {
	if len(bins) == 0 {
		return nil
	}
	// -z: пути разделены NUL и не квотятся (иначе кириллица/пробелы приедут в кавычках)
	out, err := exec.Command("git", "diff", "--cached", "--name-only", "-z", "--diff-filter=d").Output()
	if err != nil {
		return nil // сам diff уже отработал в scanStaged — здесь молча пропускаем
	}
	var leaks []leak
	for _, path := range strings.Split(string(out), "\x00") {
		if path == "" {
			continue
		}
		// путь от корня репозитория; ":путь" в ревизии git — тоже от корня
		blob, berr := exec.Command("git", "show", ":"+path).Output()
		if berr != nil || len(blob) > scanMaxFileBytes {
			continue
		}
		for raw, refs := range bins {
			if bytes.Contains(blob, []byte(raw)) {
				leaks = append(leaks, leak{path, refs})
			}
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
