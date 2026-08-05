package command

// sec stats — что из CLI реально используется, а что заведено и лежит мёртвым
// грузом. Считает локальный счётчик (internal/stats), а «ни разу» вычисляет,
// вычитая увиденное из полного списка команд и флагов, который и так ведётся
// для автодополнения (completionSubcommands / completionFlags).

import (
	"encoding/json"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kaidstor/sec/internal/stats"
)

func statsCommand(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	var days int
	var all, asJSON bool
	fs.IntVar(&days, "days", 14, "сколько последних дней показать в разбивке (0 — не показывать)")
	fs.BoolVar(&all, "all", false, "показать и команды, которых ни разу не было (обычно только в сводке снизу)")
	fs.BoolVar(&asJSON, "json", false, "машинный вывод JSON")
	_ = fs.Parse(args)

	u := stats.Load()
	unusedCmds, unusedFlags := neverUsed(u)

	if asJSON {
		out := struct {
			File        string                    `json:"file"`
			Keys        map[string]*stats.Counter `json:"keys"`
			Days        map[string]map[string]int `json:"days"`
			UnusedCmds  []string                  `json:"unusedCommands"`
			UnusedFlags []string                  `json:"unusedFlags"`
		}{stats.Path(), u.Keys, u.Days, unusedCmds, unusedFlags}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	if len(u.Keys) == 0 {
		fmt.Printf("счётчик пуст — %s появится после первых команд\n", stats.Path())
		fmt.Println("(отключается переменной SEC_NO_USAGE=1)")
		return 0
	}

	// команды (ключи без пробела) от частых к редким
	type row struct {
		name string
		s    *stats.Counter
	}
	var rows []row
	for k, s := range u.Keys {
		if !strings.Contains(k, " ") {
			rows = append(rows, row{k, s})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].s.N != rows[j].s.N {
			return rows[i].s.N > rows[j].s.N
		}
		return rows[i].name < rows[j].name
	})

	fmt.Printf("%-12s %8s  %-12s %s\n", "команда", "запусков", "последний", "флаги, которыми пользовались")
	for _, r := range rows {
		line := fmt.Sprintf("%-12s %8d  %-12s %s", r.name, r.s.N, shortDay(r.s.Last), usedFlagsOf(u, r.name))
		fmt.Println(strings.TrimRight(line, " "))
	}
	if all {
		for _, c := range unusedCmds {
			fmt.Printf("%-12s %8s  %-12s\n", c, "—", "ни разу")
		}
	}

	if days > 0 {
		fmt.Printf("\nпо дням (последние %d):\n", days)
		shown := 0
		for _, d := range u.SortedDays() {
			if shown >= days {
				break
			}
			shown++
			counts := u.Days[d]
			total := 0
			for _, n := range counts {
				total += n
			}
			fmt.Printf("  %s  %4d   %s\n", shortDay(d), total, topOfDay(counts))
		}
		if shown == 0 {
			fmt.Println("  пусто")
		}
	}

	fmt.Println()
	if len(unusedCmds) > 0 {
		fmt.Printf("ни разу не использовались команды (%d): %s\n", len(unusedCmds), strings.Join(unusedCmds, ", "))
	}
	if len(unusedFlags) > 0 {
		fmt.Printf("ни разу не использовались флаги (%d): %s\n", len(unusedFlags), strings.Join(unusedFlags, ", "))
	}
	if len(unusedCmds) == 0 && len(unusedFlags) == 0 {
		fmt.Println("использовано всё, что есть в CLI")
	}
	return 0
}

// neverUsed вычитает увиденное из полной поверхности CLI. Флаги считаются
// только у команд, которые вообще запускались: «не использовал --staged» у
// команды, которую не открывал ни разу, — шум, а не находка.
func neverUsed(u *stats.File) (cmds, flags []string) {
	for _, c := range completionSubcommands {
		if u.Keys[c] == nil {
			cmds = append(cmds, c)
			continue
		}
		for _, f := range completionFlags[c] {
			if f == "--env" { // длинная форма -e, отдельной фичей не считается
				continue
			}
			if u.Keys[c+" "+f] == nil {
				flags = append(flags, c+" "+f)
			}
		}
	}
	sort.Strings(cmds)
	sort.Strings(flags)
	return cmds, flags
}

// usedFlagsOf — флаги команды, которыми реально пользовались, от частых к редким.
func usedFlagsOf(u *stats.File, cmd string) string {
	type fl struct {
		name string
		n    int
	}
	var out []fl
	for k, s := range u.Keys {
		if name, ok := strings.CutPrefix(k, cmd+" "); ok {
			out = append(out, fl{name, s.N})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].name < out[j].name
	})
	parts := make([]string, 0, len(out))
	for _, f := range out {
		parts = append(parts, fmt.Sprintf("%s×%d", f.name, f.n))
	}
	return strings.Join(parts, " ")
}

// topOfDay — команды дня от частых к редким, одной строкой.
func topOfDay(counts map[string]int) string {
	type cn struct {
		name string
		n    int
	}
	var out []cn
	for k, n := range counts {
		out = append(out, cn{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].name < out[j].name
	})
	parts := make([]string, 0, len(out))
	for _, c := range out {
		parts = append(parts, fmt.Sprintf("%s×%d", c.name, c.n))
	}
	return strings.Join(parts, " ")
}

// shortDay переводит ключ счётчика (YYYY-MM-DD) в привычный дд.мм.гггг.
func shortDay(day string) string {
	t, err := time.Parse(stats.DayFormat, day)
	if err != nil {
		return day
	}
	return t.Format("02.01.2006")
}
