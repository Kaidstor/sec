// `sec skills` — раскладка агентского скилла (SKILL.md вкомпилирован в бинарь,
// пакет internal/skill) по каталогам агентов ~/.claude/skills и ~/.codex/skills.
// Копия помечается стампом .sec-version и дальше обновляется сама: postflight
// каска и тихий чек при каждом запуске CLI (syncSkillsStale) перезаписывают
// устаревшие копии. Симлинки (dev, npx skills add) и копии без стампа не
// трогаются — иначе апгрейд молча затирал бы чужое.
package command

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kaidstor/sec/internal/skill"
)

const skillStamp = ".sec-version"

const skillsUsage = `sec skills — агентский скилл sec у Claude/Codex

Использование:
  sec skills install              установить во все найденные каталоги агентов
  sec skills install --target claude|codex   только один агент
  sec skills install --dir <путь>            точный каталог вместо автопоиска
  sec skills install --link [<путь к SKILL.md>]  dev: симлинк на рабочее дерево
                                  (без пути — ./SKILL.md текущей папки)
  sec skills install --force      заменить и симлинк / чужую копию тоже
  sec skills status               где установлен и какой версии
`

// agentSkillDirs — каталоги скилла у агентов, найденных на машине. Агент
// считается установленным по наличию домашнего каталога (~/.claude, ~/.codex);
// самого skills/ может ещё не быть — install создаст.
func agentSkillDirs() [][2]string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out [][2]string
	for _, a := range [][2]string{{"claude", ".claude"}, {"codex", ".codex"}} {
		if st, err := os.Stat(filepath.Join(home, a[1])); err == nil && st.IsDir() {
			out = append(out, [2]string{a[0], filepath.Join(home, a[1], "skills", "sec")})
		}
	}
	return out
}

type skillState int

const (
	skillMissing skillState = iota
	skillSymlink            // SKILL.md внутри — симлинк (dev / npx), обновляется сам, не трогаем
	skillManaged            // наша копия со стампом — её и обновляем
	skillManual             // каталог без стампа — разложен руками, обходим стороной
)

// skillStateOf различает состояния по SKILL.md и стампу. Симлинк проверяется
// первым: у sec дистрибуция через npx skills add тоже кладёт симлинк — его
// самолечение видеть не должно, даже если рядом остался стамп.
func skillStateOf(dir string) (skillState, string) {
	md := filepath.Join(dir, "SKILL.md")
	if fi, err := os.Lstat(md); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink(md)
		return skillSymlink, target
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return skillMissing, ""
	}
	if v, err := os.ReadFile(filepath.Join(dir, skillStamp)); err == nil {
		return skillManaged, strings.TrimSpace(string(v))
	}
	return skillManual, ""
}

// installSkillCopy пишет копию скилла со стампом. Существующие копии (наши и
// ручные) перезаписываются — явный install и есть согласие; симлинк — только
// с force.
func installSkillCopy(dir string, force bool) error {
	md := filepath.Join(dir, "SKILL.md")
	if fi, err := os.Lstat(md); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if !force {
			return fmt.Errorf("%s — симлинк, оставлен как есть (--force — заменить копией)", md)
		}
		if err := os.Remove(md); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(md, []byte(skill.MD), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, skillStamp), []byte(version+"\n"), 0o644)
}

// linkSkill — dev-режим: SKILL.md в каталоге агента становится симлинком на
// файл в рабочем дереве, правки видны сразу. Свой симлинк и своя копия
// пересоздаются без force, чужая копия без стампа — только с ним.
func linkSkill(dir, target string, force bool) error {
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		target = filepath.Join(target, "SKILL.md")
	}
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("%s недоступен: %w", target, err)
	}
	state, _ := skillStateOf(dir)
	if state == skillManual && !force {
		return fmt.Errorf("%s — копия без стампа (не наша), --force — заменить", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	md := filepath.Join(dir, "SKILL.md")
	_ = os.Remove(md)
	// симлинк не носит стамп: самолечению здесь делать нечего
	_ = os.Remove(filepath.Join(dir, skillStamp))
	return os.Symlink(target, md)
}

// syncSkillsStale — самолечение при каждом запуске CLI: устаревшая наша копия
// молча перезаписывается. Бест-эффорт, ошибки глотаются. Локальная сборка
// (version == "dev") копии не трогает — иначе dev-бинарь затирал бы
// релизные стампы своим "dev".
func syncSkillsStale(cmd string) {
	if version == "dev" || cmd == "__complete" || cmd == "__clearclip" {
		return
	}
	for _, a := range agentSkillDirs() {
		if state, v := skillStateOf(a[1]); state == skillManaged && v != version {
			_ = installSkillCopy(a[1], false)
		}
	}
}

func skillsInstall(args []string) int {
	var target, dir, linkPath string
	var link, force bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--target":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "sec skills: --target требует значение (claude|codex)")
				return 2
			}
			i++
			target = args[i]
		case "--dir":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "sec skills: --dir требует путь")
				return 2
			}
			i++
			dir = args[i]
		case "--link":
			link = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				linkPath = args[i]
			}
		case "--force":
			force = true
		case "-h", "--help":
			fmt.Print(skillsUsage)
			return 0
		default:
			fmt.Fprintf(os.Stderr, "sec skills install: неизвестный аргумент %q\n", args[i])
			return 2
		}
	}

	if link && linkPath == "" {
		// без пути — SKILL.md из текущей папки: dev-запуск из корня репо
		if _, err := os.Stat("SKILL.md"); err != nil {
			fmt.Fprintln(os.Stderr, "sec skills: в текущей папке нет SKILL.md — укажи путь: --link <путь>")
			return 2
		}
		abs, err := filepath.Abs("SKILL.md")
		if err != nil {
			fmt.Fprintln(os.Stderr, "sec skills:", err)
			return 2
		}
		linkPath = abs
	}

	var dirs [][2]string
	switch {
	case dir != "":
		dirs = [][2]string{{"dir", dir}}
	default:
		all := agentSkillDirs()
		if len(all) == 0 {
			fmt.Fprintln(os.Stderr, "sec skills: не найдено ни ~/.claude, ни ~/.codex — агентов на машине нет")
			return 1
		}
		for _, a := range all {
			if target == "" || a[0] == target {
				dirs = append(dirs, a)
			}
		}
		if len(dirs) == 0 {
			fmt.Fprintf(os.Stderr, "sec skills: агент %q не найден\n", target)
			return 1
		}
	}

	code := 0
	for _, a := range dirs {
		var err error
		what := ""
		if link {
			err = linkSkill(a[1], linkPath, force)
			what = "симлинк → " + linkPath
		} else {
			err = installSkillCopy(a[1], force)
			what = "копия v" + version
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "sec: %s: %v\n", a[0], err)
			code = 1
			continue
		}
		fmt.Printf("✓ %s: %s — %s\n", a[0], what, a[1])
	}
	return code
}

func skillsStatus() int {
	all := agentSkillDirs()
	if len(all) == 0 {
		fmt.Println("агентов не найдено (нет ни ~/.claude, ни ~/.codex)")
		return 0
	}
	for _, a := range all {
		state, v := skillStateOf(a[1])
		var line string
		switch state {
		case skillMissing:
			line = "не установлен (sec skills install)"
		case skillSymlink:
			line = "симлинк → " + v + " (обновляется сам)"
		case skillManaged:
			if v == version {
				line = "копия v" + v + ", актуальна"
			} else {
				line = fmt.Sprintf("копия v%s, устарела (текущая v%s) — обновится при следующем запуске sec", v, version)
			}
		case skillManual:
			line = "копия без стампа — не обновляется; sec skills install возьмёт под управление"
		}
		fmt.Printf("%s: %s — %s\n", a[0], line, a[1])
	}
	return 0
}

func skillsCommand(args []string) int {
	if len(args) == 0 {
		fmt.Print(skillsUsage)
		return 2
	}
	switch args[0] {
	case "install":
		return skillsInstall(args[1:])
	case "status":
		return skillsStatus()
	case "-h", "--help", "help":
		fmt.Print(skillsUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "sec skills: неизвестная подкоманда %q\n", args[0])
		return 2
	}
}
