package command

// Материализация файловых секретов для sec run --file (паттерн systemd
// LoadCredential / vault agent): секрет разворачивается во временный файл 0600
// на время команды, путь уходит в env-переменную, файл удаляется по выходу.
// Ключ живёт в сторе постоянно, на диске — только пока работает команда.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kaidstor/sec/internal/store"
)

// stringList — повторяемый строковый флаг (flag.Value).
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// fileMount — разобранная спецификация --file: какой ключ, куда положить и под
// какой env-переменной отдать путь.
type fileMount struct {
	envName   string // имя env-переменной с путём (умолч. — имя ключа)
	proj, key string // внутренний адрес секрета
	dest      string // явный путь; "" — временный каталог
}

// parseFileMount разбирает "[ENV=]<KEY|proj[@prof]/KEY>[:путь]". Голый KEY —
// из проекта запуска (с его профилем); "proj/KEY" — из базового проекта без
// профиля (файловые секреты обычно живут в отдельной пачке вроде tauri-keys),
// профиль чужой пачки — явно: proj@prof/KEY.
func parseFileMount(spec, runProj string) (fileMount, error) {
	m := fileMount{}
	rest := spec
	// ENV= распознаётся однозначно: в ссылке и до неё нет ни '=', ни ':', ни '/',
	// а '=' внутри пути не совпадёт с keyRe из-за ':' перед ним
	if i := strings.IndexByte(rest, '='); i > 0 && keyRe.MatchString(rest[:i]) {
		m.envName, rest = rest[:i], rest[i+1:]
	}
	// ссылка не содержит ':' — всё после первого ':' это путь (в т.ч. "C:\…")
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		m.dest, rest = rest[i+1:], rest[:i]
		if m.dest == "" {
			return m, fmt.Errorf("--file %s: пустой путь после ':'", spec)
		}
	}
	if p, k, ok := strings.Cut(rest, "/"); ok {
		base, prof, _ := splitProfile(p)
		if !projRe.MatchString(base) || !keyRe.MatchString(k) || (prof != "" && !profileRe.MatchString(prof)) {
			return m, fmt.Errorf("--file %s: некорректная ссылка %q (нужно KEY или proj[@prof]/KEY)", spec, rest)
		}
		m.proj, m.key = store.ProjKey(base, prof), k
	} else {
		if !keyRe.MatchString(rest) {
			return m, fmt.Errorf("--file %s: некорректное имя ключа %q", spec, rest)
		}
		m.proj, m.key = runProj, rest
	}
	if m.envName == "" {
		m.envName = m.key
	}
	return m, nil
}

// parseFileMounts разбирает все --file и ловит дубли env-имён: молча перекрыть
// один путь другим значит подсунуть команде не тот файл.
func parseFileMounts(specs []string, runProj string) ([]fileMount, error) {
	var out []fileMount
	seen := map[string]string{}
	for _, spec := range specs {
		m, err := parseFileMount(spec, runProj)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[m.envName]; dup {
			return nil, fmt.Errorf("--file: env-переменная %s задана дважды (%s и %s) — разведи через ENV=", m.envName, prev, spec)
		}
		seen[m.envName] = spec
		out = append(out, m)
	}
	return out, nil
}

// materializeMounts пишет секреты во временные файлы и возвращает карту
// env-переменная → абсолютный путь плюс функцию удаления всего созданного.
// При ошибке прибирает уже созданное сам (вызывающему звать cleanup не нужно).
func materializeMounts(st *store.Store, mounts []fileMount) (map[string]string, func(), error) {
	var files, dirs []string
	cleanup := func() {
		for _, f := range files {
			os.Remove(f)
		}
		for _, d := range dirs {
			os.RemoveAll(d)
		}
	}
	env := map[string]string{}
	for _, m := range mounts {
		sec, _, _, ok := st.Lookup(m.proj, m.key)
		if !ok {
			cleanup()
			return nil, nil, fmt.Errorf("нет %s/%s (--file; смотри: sec find %s)", m.proj, m.key, m.key)
		}
		raw, err := sec.Bytes()
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("%s/%s: %v", m.proj, m.key, err)
		}
		dest := m.dest
		if dest == "" {
			// каталог на каждый секрет: 0700 от MkdirTemp, имена файлов не сталкиваются
			dir, derr := os.MkdirTemp("", "sec-run-")
			if derr != nil {
				cleanup()
				return nil, nil, fmt.Errorf("временный каталог: %v", derr)
			}
			dirs = append(dirs, dir)
			name := m.key
			if sec.Meta != nil && sec.Meta.Filename != "" {
				if base := safeBaseName(sec.Meta.Filename); base != "" {
					name = base
				}
			}
			dest = filepath.Join(dir, name)
		}
		// O_EXCL: по существующему пути не пишем — файл не наш, удалять его по
		// выходу было бы неожиданно (а перезапись уничтожила бы чужое содержимое)
		f, oerr := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if oerr != nil {
			cleanup()
			if os.IsExist(oerr) {
				return nil, nil, fmt.Errorf("--file: %s уже существует — не перезаписываю (удали или укажи другой путь)", dest)
			}
			return nil, nil, fmt.Errorf("--file: %v", oerr)
		}
		files = append(files, dest)
		if _, werr := f.Write(raw); werr != nil {
			f.Close()
			cleanup()
			return nil, nil, fmt.Errorf("запись %s: %v", dest, werr)
		}
		if cerr := f.Close(); cerr != nil {
			cleanup()
			return nil, nil, fmt.Errorf("запись %s: %v", dest, cerr)
		}
		abs, aerr := filepath.Abs(dest)
		if aerr != nil {
			abs = dest
		}
		env[m.envName] = abs
	}
	return env, cleanup, nil
}
