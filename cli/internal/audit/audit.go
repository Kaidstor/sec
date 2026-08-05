package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kaidstor/sec/internal/store"
)

// ---------------------------------------------------------------------------
// Журнал обращений: append-only JSONL рядом с хранилищем. Пишутся только
// имена ключей и метаданные операции — значения в журнал не попадают никогда.
// ---------------------------------------------------------------------------

type Entry struct {
	TS     string `json:"ts"`
	Op     string `json:"op"`
	Target string `json:"target"`
	Detail string `json:"detail,omitempty"`
	By     string `json:"by,omitempty"`
}

func auditPath() string {
	return filepath.Join(filepath.Dir(store.Path()), "audit.jsonl")
}

// Path — путь к файлу журнала обращений (рядом с хранилищем).
func Path() string { return auditPath() }

// auditMaxBytes — потолок текущего файла. Ограничение не про диск (журнал
// растёт медленно), а про чтение: Read() парсит файл целиком даже ради
// `sec log -n 20`, поэтому расти без предела ему нельзя.
const auditMaxBytes = 1 << 20

// KeepDays — сколько держать архивы ротации. Год с запасом: полный годовой
// отчёт должен собираться и в последний день года, когда свежий архив уже
// создан, а данные начала года лежат в предыдущем.
const KeepDays = 400

// archivePrefix/archiveSuffix — имя архива с датой ротации:
// audit-20260805-120000.jsonl. Лексикографический порядок имён совпадает с
// хронологическим — на этом держится склейка в ReadAll.
const archivePrefix = "audit-"
const archiveSuffix = ".jsonl"
const archiveTimeFormat = "20060102-150405"

// audit пишет запись best-effort: проблемы с журналом не роняют операцию.
func Record(op, target, detail string) {
	data, err := json.Marshal(Entry{TS: store.Now(), Op: op, Target: target, Detail: detail, By: caller()})
	if err != nil {
		return
	}
	p := auditPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	if st, err := os.Stat(p); err == nil && st.Size() > auditMaxBytes {
		rotate(p, time.Now())
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sec: журнал обращений недоступен: %v\n", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

// rotate уводит текущий журнал в архив с датой и подчищает архивы старше
// KeepDays. Ротация по размеру, а удаление по возрасту файла: внутри архива
// лежат записи ещё старше него, поэтому хранится всегда не меньше KeepDays.
func rotate(p string, now time.Time) {
	dir := filepath.Dir(p)
	arch := filepath.Join(dir, archivePrefix+now.Format(archiveTimeFormat)+archiveSuffix)
	if os.Rename(p, arch) != nil {
		return
	}
	for _, a := range Archives() {
		ts, ok := archiveTime(filepath.Base(a))
		if ok && now.Sub(ts) > KeepDays*24*time.Hour {
			_ = os.Remove(a)
		}
	}
}

// archiveTime достаёт дату ротации из имени архива.
func archiveTime(name string) (time.Time, bool) {
	s, ok := strings.CutPrefix(name, archivePrefix)
	if !ok {
		return time.Time{}, false
	}
	s, ok = strings.CutSuffix(s, archiveSuffix)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation(archiveTimeFormat, s, time.Local)
	return t, err == nil
}

// Archives — пути архивов журнала от старых к свежим. Файл audit.jsonl.1
// остался от прежней схемы ротации: читаем его, но по возрасту не удаляем —
// даты в имени нет, а гадать по mtime ради одного легаси-файла не стоит.
func Archives() []string {
	dir := filepath.Dir(auditPath())
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if _, ok := archiveTime(e.Name()); ok {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out) // имя содержит дату — лексикографический порядок и есть хронологический
	if legacy := auditPath() + ".1"; fileExists(legacy) {
		out = append([]string{legacy}, out...)
	}
	return out
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// Read — записи текущего файла. Быстрый путь для `sec log -n 20`: годовую
// историю ради двадцати последних строк парсить незачем.
func Read() []Entry {
	return parse(auditPath())
}

// ReadAll — весь журнал, включая архивы, по возрастанию времени (`sec log --all`).
func ReadAll() []Entry {
	var out []Entry
	for _, a := range Archives() {
		out = append(out, parse(a)...)
	}
	return append(out, Read()...)
}

func parse(path string) []Entry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []Entry
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e Entry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}
