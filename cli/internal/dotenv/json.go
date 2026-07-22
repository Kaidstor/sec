package dotenv

// JSON как источник набора KEY=VALUE для sec import: объект вида
// {"DB_PASS": "…"}. Вложенные объекты разворачиваются через "_"
// ({"db":{"pass":…}} → DB_PASS), массивы и прочие структуры сохраняются
// компактным JSON-текстом значения. Ключи приводятся к имени env-переменной
// (верхний регистр, всё лишнее → "_"), негодные пропускаются с
// предупреждением. Значения не трогаются и никуда не печатаются.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ParseJSON разбирает JSON-объект в KEY→VALUE. Вторым результатом —
// предупреждения (пропущенные ключи, коллизии имён), третьим — ошибка формата.
func ParseJSON(data string) (map[string]string, []string, error) {
	dec := json.NewDecoder(strings.NewReader(strings.TrimPrefix(data, "\ufeff")))
	dec.UseNumber() // числа как в исходнике: 1e9 не должно стать 1e+09
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, nil, fmt.Errorf("не разобрать JSON: %w", err)
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf(`ожидался JSON-объект {"KEY": "значение"}, а не %s`, jsonKind(root))
	}

	out := map[string]string{}
	var warns []string
	var walk func(prefix []string, m map[string]any)
	walk = func(prefix []string, m map[string]any) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys) // обход детерминированный: коллизии разрешаются одинаково
		for _, k := range keys {
			path := append(append([]string{}, prefix...), k)
			if nested, ok := m[k].(map[string]any); ok {
				walk(path, nested)
				continue
			}
			name := envKeyName(path)
			label := strings.Join(path, ".")
			if !keyRe.MatchString(name) || strings.Trim(name, "_") == "" {
				warns = append(warns, fmt.Sprintf("ключ %q не приводится к имени env-переменной, пропущен", label))
				continue
			}
			v, ok := jsonValue(m[k])
			if !ok {
				warns = append(warns, fmt.Sprintf("ключ %q: значение null, пропущен", label))
				continue
			}
			if _, dup := out[name]; dup {
				warns = append(warns, fmt.Sprintf("ключ %q даёт уже занятое имя %s, взято последнее", label, name))
			}
			out[name] = v
		}
	}
	walk(nil, obj)
	return out, warns, nil
}

// jsonValue переводит значение JSON в строку: строки как есть, числа и bool
// текстом, массивы и вложенные структуры — компактным JSON. null → ok=false.
func jsonValue(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "", false
		}
		return string(b), true
	}
}

// envKeyName склеивает путь в имя env-переменной: части через "_", буквы в
// верхний регистр, всё остальное — в "_" (db.pass → DB_PASS).
func envKeyName(path []string) string {
	var b strings.Builder
	for i, p := range path {
		if i > 0 {
			b.WriteByte('_')
		}
		for _, r := range p {
			switch {
			case r >= 'a' && r <= 'z':
				b.WriteRune(r - ('a' - 'A'))
			case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
				b.WriteRune(r)
			default:
				b.WriteByte('_')
			}
		}
	}
	return b.String()
}

func jsonKind(v any) string {
	switch v.(type) {
	case []any:
		return "массив"
	case string:
		return "строка"
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", v)
}
