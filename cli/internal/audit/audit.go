package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

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

const auditMaxBytes = 1 << 20 // ~1 МБ, дальше ротация в audit.jsonl.1

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
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sec: журнал обращений недоступен: %v\n", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

// caller — имя родительского процесса (кто дернул sec: zsh, node, claude…).
func caller() string {
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(os.Getppid())).Output()
	if err != nil {
		return ""
	}
	return filepath.Base(strings.TrimSpace(string(out)))
}

func Read() []Entry {
	data, err := os.ReadFile(auditPath())
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
