package command

// Манифест .sec и команда check. Формат .sec — директивы и/или голый список
// ключей (обратная совместимость):
//
//	# .sec для сервиса some-bot
//	project:  some-bot
//	profiles: commercial, max
//	default:  commercial
//	keys:     BOT_TOKEN, DB_PASSWORD, COMPANY_ID
//
// Профиль (profiles) — необязательная третья ось; default подставляется,
// когда адрес без '@'. `sec check` валидирует, что все keys заведены в
// соответствующем проекте (service либо service@profile), и годится как гейт.

import (
	"github.com/kaidstor/sec/internal/store"

	"flag"
	"fmt"
	"os"
	"strings"
)

type secConfig struct {
	Project  string
	Profiles []string
	Default  string
	Keys     []string
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseSecFile разбирает .sec: директивы project/profiles/default/keys плюс
// голые строки-ключи. Возвращает также предупреждения о некорректных строках.
func parseSecFile(text string) (secConfig, []string) {
	var c secConfig
	var warns []string
	for i, raw := range strings.Split(text, "\n") {
		line := raw
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "project":
				c.Project = strings.TrimSpace(v)
			case "default":
				c.Default = strings.TrimSpace(v)
			case "profiles":
				c.Profiles = append(c.Profiles, splitList(v)...)
			case "envs":
				warns = append(warns, fmt.Sprintf("строка %d: директива envs: переименована в profiles: — поправь .sec (значения не применены)", i+1))
			case "keys":
				c.Keys = append(c.Keys, splitList(v)...)
			default:
				warns = append(warns, fmt.Sprintf("строка %d: неизвестная директива %q", i+1, raw))
			}
			continue
		}
		c.Keys = append(c.Keys, line) // голый ключ (старый формат-список)
	}
	return c, warns
}

func loadSecConfig() (secConfig, bool) {
	data, err := os.ReadFile(".sec")
	if err != nil {
		return secConfig{}, false
	}
	c, _ := parseSecFile(string(data))
	return c, true
}

// secDefaultProfile — дефолтный профиль из .sec в текущей папке, если .sec
// есть и его project совпадает с сервисом (либо project не задан — тогда
// применяем к сервису по имени текущей папки). Иначе "".
func secDefaultProfile(service string) string {
	c, ok := loadSecConfig()
	if !ok || c.Default == "" {
		return ""
	}
	if c.Project != "" {
		if c.Project != service {
			return ""
		}
	} else if service != cwdProject() {
		return ""
	}
	return c.Default
}

func checkCommand(args []string) int {
	proj, rest := splitArgs(args)
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	var file string
	var allProfiles bool
	fs.StringVar(&file, "file", ".sec", "манифест требуемых ключей")
	fs.BoolVar(&allProfiles, "all-profiles", false, "проверить все профили из profiles, а не только выбранный")
	_ = fs.Parse(rest)
	if proj == "" {
		proj = fs.Arg(0)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		die("чтение %s: %v (создай список требуемых ключей, по одному на строку)", file, err)
	}
	cfg, warns := parseSecFile(string(data))
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "sec: %s: %s\n", file, w)
	}
	// сервис: из аргумента (может нести @profile), иначе из .sec project,
	// иначе имя папки
	svcArg := proj
	if svcArg == "" {
		svcArg = cfg.Project
	}
	service, profile, explicit := splitProfile(svcArg)
	if service == "" {
		service = cwdProject()
	}
	if len(cfg.Keys) == 0 {
		die("в %s нет ни одного ключа", file)
	}

	// какие профили проверять
	if !explicit {
		profile = secDefaultProfile(service)
	}
	profiles := []string{profile}
	if allProfiles && len(cfg.Profiles) > 0 {
		profiles = cfg.Profiles
	}

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	missingTotal := 0
	for _, prof := range profiles {
		checkProfile(prof)
		sp := store.ProjKey(service, prof)
		keys := st.Projects[sp]
		var missing []string
		for _, k := range cfg.Keys {
			if strings.IndexByte(k, '/') >= 0 { // допускаем proj/KEY в списке
				continue
			}
			if _, ok := keys[k]; !ok {
				missing = append(missing, k)
			}
		}
		if len(missing) == 0 {
			fmt.Printf("%s: все ключи на месте (%d)\n", sp, len(cfg.Keys))
		} else {
			missingTotal += len(missing)
			fmt.Printf("%s: не хватает %d из %d — %s\n", sp, len(missing), len(cfg.Keys), strings.Join(missing, ", "))
		}
	}
	if missingTotal > 0 {
		return 2
	}
	return 0
}
