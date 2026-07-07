// Package infisical — мост к Infisical через их CLI (`infisical`). Вынесен в
// отдельный пакет, чтобы бэкенд был заменяемым: сейчас это CLI, позже без
// изменения вызывающего кода можно подставить REST API.
//
// Значения секретов не проходят через argv: pull забирает их из stdout
// (`infisical export --format=json`), push отдаёт через временный .env-файл
// (`infisical secrets set --file`, 0600, удаляется сразу после). В argv уходят
// только имена окружения/пути/проекта — не секреты.
package infisical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Ref адресует набор секретов в Infisical. Env/Path имеют дефолты CLI
// (dev, /). ProjectID/Token опциональны: без ProjectID CLI берёт проект из
// окружающего .infisical.json (как `infisical run/export` в папке сервиса).
type Ref struct {
	Env       string
	Path      string
	ProjectID string
	Token     string
}

const binary = "infisical"

// Available проверяет, что CLI установлен.
func Available() error {
	if _, err := exec.LookPath(binary); err != nil {
		return errors.New("не найден infisical CLI (brew install infisical/get-cli/infisical); нужен `infisical login`")
	}
	return nil
}

func (r Ref) args() []string {
	var a []string
	if r.Env != "" {
		a = append(a, "--env="+r.Env)
	}
	if r.Path != "" {
		a = append(a, "--path="+r.Path)
	}
	if r.ProjectID != "" {
		a = append(a, "--projectId="+r.ProjectID)
	}
	if r.Token != "" {
		a = append(a, "--token="+r.Token)
	}
	return a
}

// run запускает infisical, отделяя stdout (данные) от stderr (диагностика).
func run(args ...string) ([]byte, error) {
	cmd := exec.Command(binary, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return nil, fmt.Errorf("infisical: %s", msg)
		}
		return nil, fmt.Errorf("infisical: %w", err)
	}
	return out.Bytes(), nil
}

// Pull забирает секреты из Infisical как map[KEY]VALUE.
func Pull(ref Ref) (map[string]string, error) {
	if err := Available(); err != nil {
		return nil, err
	}
	args := append([]string{"export", "--format=json", "--silent"}, ref.args()...)
	out, err := run(args...)
	if err != nil {
		return nil, err
	}
	return parseExportJSON(out)
}

// parseExportJSON понимает и объект {"KEY":"val"}, и массив
// [{"key"/"secretKey":…,"value"/"secretValue":…}] — на случай разных версий CLI.
func parseExportJSON(b []byte) (map[string]string, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var obj map[string]string
	if err := json.Unmarshal(b, &obj); err == nil && obj != nil {
		return obj, nil
	}
	var arr []map[string]string
	if err := json.Unmarshal(b, &arr); err == nil {
		out := map[string]string{}
		for _, e := range arr {
			k := firstNonEmpty(e["key"], e["secretKey"], e["Key"], e["SecretKey"])
			v := firstNonEmpty(e["value"], e["secretValue"], e["Value"], e["SecretValue"])
			if k != "" {
				out[k] = v
			}
		}
		return out, nil
	}
	return nil, errors.New("не удалось разобрать вывод infisical export (неожиданный JSON)")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Push отправляет секреты в Infisical. Значения уходят через временный
// .env-файл (0600), не через argv; файл удаляется сразу после.
func Push(ref Ref, kv map[string]string) error {
	if err := Available(); err != nil {
		return err
	}
	if len(kv) == 0 {
		return errors.New("нет ключей для отправки")
	}
	tmp, err := os.CreateTemp("", "sec-infisical-*.env")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_ = tmp.Chmod(0o600)

	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(envLine(k, kv[k]))
		b.WriteByte('\n')
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	args := append([]string{"secrets", "set", "--file", tmp.Name(), "--silent"}, ref.args()...)
	_, err = run(args...)
	return err
}

// envLine форматирует пару KEY=VALUE для .env: значения без спецсимволов
// пишутся как есть, остальные — в двойных кавычках с экранированием.
func envLine(k, v string) string {
	if v != "" && !strings.ContainsAny(v, " \t\"'#\\\n`") {
		return k + "=" + v
	}
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
	return k + `="` + esc + `"`
}
