package command

// Манифест .sec и команда check. Формат .sec — директивы и/или голый список
// ключей (обратная совместимость):
//
//	# .sec для сервиса some-bot
//	project: some-bot
//	envs:    commercial, max
//	default: commercial
//	keys:    BOT_TOKEN, DB_PASSWORD, COMPANY_ID
//
// Инстанс/окружение (envs) — необязательная третья ось; default подставляется,
// когда -e не указан. `sec check` валидирует, что все keys заведены в
// соответствующем проекте (service либо service@env), и годится как гейт.

import (
	"github.com/kaidstor/sec/internal/store"

	"flag"
	"fmt"
	"os"
	"strings"
)

type secConfig struct {
	Project string
	Envs    []string
	Default string
	Keys    []string
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

// parseSecFile разбирает .sec: директивы project/envs/default/keys плюс голые
// строки-ключи. Возвращает также предупреждения о некорректных именах ключей.
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
			case "envs":
				c.Envs = append(c.Envs, splitList(v)...)
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

// secDefaultEnv — дефолтный инстанс из .sec в текущей папке, если .sec есть и его
// project совпадает с сервисом (либо project не задан — тогда применяем к
// сервису по имени текущей папки). Иначе "".
func secDefaultEnv(service string) string {
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

// resolvedEnv отдаёт явный -e, иначе дефолт из .sec для этого сервиса.
func resolvedEnv(explicit, service string) string {
	if explicit != "" {
		return explicit
	}
	return secDefaultEnv(service)
}

// refService — имя сервиса из ссылки "<service>/<KEY>" (или cwd, если без "/").
func refService(ref string) string {
	if svc, _, ok := strings.Cut(ref, "/"); ok {
		return svc
	}
	return cwdProject()
}

func checkCommand(args []string) int {
	proj, rest := splitArgs(args)
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	var file string
	var allEnvs bool
	fs.StringVar(&file, "file", ".sec", "манифест требуемых ключей")
	fs.BoolVar(&allEnvs, "all-envs", false, "проверить все инстансы из envs, а не только выбранный")
	getEnv := addEnvFlag(fs)
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
	// сервис: из аргумента, иначе из .sec project, иначе имя папки
	service := proj
	if service == "" {
		service = cfg.Project
	}
	if service == "" {
		service = cwdProject()
	}
	if len(cfg.Keys) == 0 {
		die("в %s нет ни одного ключа", file)
	}

	// какие инстансы проверять
	envs := []string{resolvedEnv(getEnv(), service)}
	if allEnvs && len(cfg.Envs) > 0 {
		envs = cfg.Envs
	}

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	missingTotal := 0
	for _, env := range envs {
		checkEnv(env)
		sp := store.ProjKey(service, env)
		keys := st.Projects[sp]
		var missing []string
		for _, k := range cfg.Keys {
			base := k
			if i := strings.IndexByte(base, '/'); i >= 0 { // допускаем proj/KEY в списке
				continue
			}
			if _, ok := keys[k]; !ok {
				missing = append(missing, k)
			}
		}
		label := service
		if env != "" {
			label = service + " -e " + env
		}
		if len(missing) == 0 {
			fmt.Printf("%s: все ключи на месте (%d)\n", label, len(cfg.Keys))
		} else {
			missingTotal += len(missing)
			fmt.Printf("%s: не хватает %d из %d — %s\n", label, len(missing), len(cfg.Keys), strings.Join(missing, ", "))
		}
	}
	if missingTotal > 0 {
		return 2
	}
	return 0
}
