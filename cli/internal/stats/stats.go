package stats

// Локальный счётчик использования CLI: что реально применяется, а что заведено
// и лежит мёртвым грузом. Пишутся ТОЛЬКО имена команд и флагов — ни значений,
// ни имён проектов и ключей: этот файл должен быть безопасен сам по себе.
//
// Отдельно от audit.jsonl (журнала обращений) намеренно: тот ротируется по
// размеру и выбрасывает хвост, а вопрос «использовалось ли это хоть раз» без
// полной истории не ответить. Здесь не события, а счётчики — файл не растёт.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kaidstor/sec/internal/store"
)

// maxDays — сколько дней подробной разбивки держим. Итоги за всё время
// (Keys) не обрезаются никогда, иначе «ни разу не использовалось» соврёт.
const maxDays = 400

const fileVersion = 1

// DayFormat — ключ дневной разбивки (он же формат First/Last).
const DayFormat = "2006-01-02"

// Stat — итог по одной команде или паре «команда флаг» за всё время.
type Counter struct {
	N     int    `json:"n"`
	First string `json:"first"`
	Last  string `json:"last"`
}

// File — весь счётчик. Keys держит и команды ("run"), и флаги ("run --only");
// Days — только команды: разбивка по флагам ещё и по дням раздула бы файл,
// а вопросов, на которые она отвечает, нет.
type File struct {
	Version int                       `json:"version"`
	Keys    map[string]*Counter       `json:"keys"`
	Days    map[string]map[string]int `json:"days"`
}

// Path — файл счётчиков рядом с хранилищем и журналом.
func Path() string { return filepath.Join(filepath.Dir(store.Path()), "usage.json") }

// Load читает счётчики best-effort: битый или отсутствующий файл — пустая
// статистика, а не ошибка. Файл более новой версии не читаем и не трогаем.
func Load() *File {
	f := &File{Version: fileVersion, Keys: map[string]*Counter{}, Days: map[string]map[string]int{}}
	data, err := os.ReadFile(Path())
	if err != nil {
		return f
	}
	var got File
	if json.Unmarshal(data, &got) != nil || got.Version > fileVersion {
		return f
	}
	if got.Keys != nil {
		f.Keys = got.Keys
	}
	if got.Days != nil {
		f.Days = got.Days
	}
	return f
}

// Record отмечает один запуск команды и переданные ей флаги. Как и журнал —
// best-effort: любая проблема со счётчиками не должна ронять саму операцию.
// Выключается переменной SEC_NO_USAGE.
func Record(cmd string, flags []string, now time.Time) {
	if cmd == "" || os.Getenv("SEC_NO_USAGE") != "" {
		return
	}
	day := now.Format(DayFormat)
	f := Load()

	bump := func(key string) {
		s := f.Keys[key]
		if s == nil {
			s = &Counter{First: day}
			f.Keys[key] = s
		}
		s.N++
		s.Last = day
	}
	bump(cmd)
	for _, fl := range flags {
		bump(cmd + " " + fl)
	}
	if f.Days[day] == nil {
		f.Days[day] = map[string]int{}
	}
	f.Days[day][cmd]++

	f.prune()
	f.save()
}

// prune оставляет только последние maxDays дней разбивки.
func (f *File) prune() {
	if len(f.Days) <= maxDays {
		return
	}
	days := make([]string, 0, len(f.Days))
	for d := range f.Days {
		days = append(days, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(days))) // формат YYYY-MM-DD сортируется лексикографически
	for _, d := range days[maxDays:] {
		delete(f.Days, d)
	}
}

// save пишет файл целиком через tmp+rename: параллельный запуск sec может
// потерять свой инкремент (для счётчиков не страшно), но недописанного JSON
// на диске не окажется.
func (f *File) save() {
	f.Version = fileVersion
	data, err := json.Marshal(f)
	if err != nil {
		return
	}
	p := Path()
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, data, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, p)
}

// SortedDays — дни разбивки от свежих к старым.
func (f *File) SortedDays() []string {
	days := make([]string, 0, len(f.Days))
	for d := range f.Days {
		days = append(days, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(days)))
	return days
}
