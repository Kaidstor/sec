package command

// Правила redact для секретов, которых нет в сторе: значение поля с секретным
// именем (BOT_TOKEN, POSTGRES_PASSWORD, apiKey, Authorization), пароль в URI
// (scheme://user:pass@host) и тело PEM-ключа. Значения стора меняются раньше
// и под своим именем; правила добивают то, чего стор не знает. Это эвристика,
// а не DLP: секрет в поле с невинным именем она не увидит.

import (
	"regexp"
	"strings"
	"unicode"
)

// redactedTag — общее начало всех плейсхолдеров: по нему правила узнают уже
// скрытое стором значение и не считают его второй раз.
const redactedTag = "[redacted"

func redactedLabel(label string) string { return redactedTag + ":" + label + "]" }

func isRedacted(s string) bool { return strings.Contains(s, redactedTag) }

var (
	placeholderField = redactedLabel("field")
	placeholderURI   = redactedLabel("uri")
	placeholderPEM   = redactedLabel("pem")
)

type ruleStats struct {
	fields map[string]int
	uri    int
	pem    int
}

func (s *ruleStats) total() int {
	n := s.uri + s.pem
	for _, c := range s.fields {
		n += c
	}
	return n
}

var (
	secretWords = map[string]bool{
		"token": true, "tokens": true, "secret": true, "secrets": true,
		"password": true, "passwords": true, "passwd": true, "pwd": true, "pass": true,
		"passphrase": true, "credential": true, "credentials": true, "creds": true,
		"dsn": true, "cookie": true, "authorization": true, "apikey": true, "privatekey": true,
	}
	// «key» сам по себе слишком частый (`"key": "theme"`), секретен только с уточнением.
	keyQualifiers = map[string]bool{
		"api": true, "private": true, "access": true, "secret": true, "signing": true,
		"encryption": true, "master": true, "client": true,
	}
	// Хвосты, которые делают имя настройкой про секрет, а не самим секретом:
	// POSTGRES_PASSWORD_FILE, TOKEN_URL, PASSWORD_MIN_LENGTH.
	notSecretTail = map[string]bool{
		"file": true, "path": true, "url": true, "uri": true, "endpoint": true, "host": true,
		"ttl": true, "length": true, "len": true, "expires": true, "expiry": true, "lifetime": true,
		"timeout": true, "domain": true, "header": true, "name": true, "type": true,
		"enabled": true, "required": true, "policy": true, "min": true, "max": true,
		"count": true, "mode": true, "in": true,
	}
)

// keyWords режет имя на слова: BOT_TOKEN, bot-token, botToken → [bot token].
func keyWords(key string) []string {
	var b strings.Builder
	rs := []rune(key)
	for i, r := range rs {
		if i > 0 && unicode.IsUpper(r) && unicode.IsLower(rs[i-1]) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return strings.FieldsFunc(b.String(), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// secretNeedles — подстроки, без которых ни одно слово из secretWords и ни
// «key» с уточнением не сложится: дешёвый отсев до keyWords, который на JSON-логе
// зовётся на каждый ключ каждой строки.
var secretNeedles = []string{"token", "secret", "pass", "pwd", "cred", "dsn", "cookie", "authorization", "key"}

func sensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	hasNeedle := false
	for _, n := range secretNeedles {
		if strings.Contains(lower, n) {
			hasNeedle = true
			break
		}
	}
	if !hasNeedle {
		return false
	}
	w := keyWords(key)
	if len(w) == 0 || notSecretTail[w[len(w)-1]] {
		return false
	}
	for i, x := range w {
		if secretWords[x] {
			return true
		}
		if x == "key" && i > 0 && keyQualifiers[w[i-1]] {
			return true
		}
	}
	return false
}

var (
	reNumeric     = regexp.MustCompile(`^[0-9]+$`)
	reVarRef      = regexp.MustCompile(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`)
	reTemplate    = regexp.MustCompile(`^\{\{.*\}\}$`)
	reAngleHolder = regexp.MustCompile(`^<[^<>]*>$`)
	reStars       = regexp.MustCompile(`^\*+$`)
)

// trivialValue — значение, которое не секрет даже в секретном поле: пусто,
// флаг, число, ссылка на переменную, шаблон, заглушка или уже скрытое.
func trivialValue(v string) bool {
	t := strings.TrimSpace(v)
	if t == "" || isRedacted(t) {
		return true
	}
	switch strings.ToLower(t) {
	case "true", "false", "null", "nil", "none", "yes", "no", "on", "off", "undefined":
		return true
	}
	return reNumeric.MatchString(t) || reVarRef.MatchString(t) || reTemplate.MatchString(t) ||
		reAngleHolder.MatchString(t) || reStars.MatchString(t)
}

// quotedEnd ищет конец строки, открытой кавычкой на глубине экранирования d
// (d=0 — "…", d=1 — \"…\" внутри JSON-строки), начиная с i. Возвращает индекс
// начала закрывающего токена (его обратных слэшей), а если строка не закрылась
// на этой строке — конец строки: незакрытое значение скрывается до конца. Кавычка закрывает, если перед ней r слэшей и
// r ≡ d (mod 2d+2): на глубине 0 — чётное число, на глубине 1 — 1, 5, …,
// а \\\" (r=3) — это кавычка внутри значения.
func quotedEnd(s string, i, d int) int {
	for j := i; j < len(s); j++ {
		if s[j] != '"' {
			continue
		}
		r := 0
		for k := j - 1; k >= i && s[k] == '\\'; k-- {
			r++
		}
		if r%(2*d+2) == d {
			return j - d
		}
	}
	return bodyLen(s)
}

func bodyLen(s string) int {
	return len(strings.TrimRight(s, "\r\n"))
}

// fieldMatch — где в строке значение секретного поля; ok=false — совпадение
// регэкспа не поле (имя не секретное, граница не та) и его надо пропустить.
type fieldMatch func(line string, m []int) (key string, vs, ve int, ok bool)

// replaceFields проходит строку слева направо и меняет значения, найденные
// match, на placeholderField.
func replaceFields(line string, re *regexp.Regexp, match fieldMatch, st *ruleStats) string {
	var b strings.Builder
	copied, from := 0, 0
	for from < len(line) {
		m := re.FindStringSubmatchIndex(line[from:])
		if m == nil {
			break
		}
		for k := range m {
			if m[k] >= 0 {
				m[k] += from
			}
		}
		key, vs, ve, ok := match(line, m)
		if !ok {
			from = max(m[1], m[0]+1)
			continue
		}
		from = max(ve, m[1])
		if trivialValue(line[vs:ve]) {
			continue
		}
		b.WriteString(line[copied:vs])
		b.WriteString(placeholderField)
		copied = ve
		st.fields[key]++
	}
	if copied == 0 {
		return line
	}
	b.WriteString(line[copied:])
	return b.String()
}

var (
	// "KEY": "value" и \"KEY\": \"value\" (JSON внутри JSON-строки).
	reJSONField = regexp.MustCompile(`(\\*)"([A-Za-z_][A-Za-z0-9_.\-]*)(\\*)"[ \t]*:[ \t]*(\\*)"`)
	// "KEY=value" — environment-массив compose / docker inspect.
	reQuotedEnv = regexp.MustCompile(`(\\*)"([A-Za-z_][A-Za-z0-9_.]*)=`)
	// KEY=value, KEY: value, --password=…, ?token=…, Authorization: Bearer …
	rePlainField = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*([=:])[ \t]*`)
)

// matchJSONField: кавычки ключа и значения должны быть одной глубины, иначе это
// не пара ключ-значение, а куски разных уровней вложенности.
func matchJSONField(line string, m []int) (string, int, int, bool) {
	d := m[3] - m[2]
	if m[7]-m[6] != d || m[9]-m[8] != d {
		return "", 0, 0, false
	}
	return matchQuotedEnv(line, m)
}

func matchQuotedEnv(line string, m []int) (string, int, int, bool) {
	key := line[m[4]:m[5]]
	if !sensitiveKey(key) {
		return "", 0, 0, false
	}
	return key, m[1], quotedEnd(line, m[1], m[3]-m[2]), true
}

const plainBoundary = " \t,;{([?&-'"

func matchPlainField(line string, m []int) (string, int, int, bool) {
	ks := m[2]
	if ks > 0 && !strings.ContainsRune(plainBoundary, rune(line[ks-1])) {
		return "", 0, 0, false
	}
	key := line[ks:m[3]]
	if !sensitiveKey(key) {
		return "", 0, 0, false
	}
	vs, body := m[1], bodyLen(line)
	if vs >= body {
		return "", 0, 0, false
	}
	switch line[vs] {
	case '"':
		return key, vs + 1, quotedEnd(line, vs+1, 0), true
	case '\'':
		if end := strings.IndexByte(line[vs+1:body], '\''); end >= 0 {
			return key, vs + 1, vs + 1 + end, true
		}
		return key, vs + 1, body, true
	}
	if line[m[4]] == '=' {
		ve := vs
		for ve < body && !strings.ContainsRune(" \t&,;\"')]}", rune(line[ve])) {
			ve++
		}
		return key, vs, ve, true
	}
	// KEY: value — значение до конца строки: «Authorization: Bearer x» с пробелом.
	return key, vs, len(strings.TrimRight(line[:body], " \t,")), true
}

// reURIPassword: пароль — жадно до последнего @ перед хостом, чтобы
// незакодированный @ в пароле не оставил хвост. Незакодированные / ? # в
// пароле ломают сам URI — такой адрес правило не узнает.
var reURIPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)([^:/?#@\s"']*):([^\s"'/?#]*)@`)

func replaceURIPasswords(line string, st *ruleStats) string {
	ms := reURIPassword.FindAllStringSubmatchIndex(line, -1)
	if ms == nil {
		return line
	}
	var b strings.Builder
	copied := 0
	for _, m := range ms {
		pw := line[m[6]:m[7]]
		if pw == "" || isRedacted(pw) {
			continue
		}
		b.WriteString(line[copied:m[6]])
		b.WriteString(placeholderURI)
		copied = m[7]
		st.uri++
	}
	if copied == 0 {
		return line
	}
	b.WriteString(line[copied:])
	return b.String()
}

var (
	rePEMBegin = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	rePEMEnd   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY-----`)
)

// replacePEM скрывает тело приватного ключа. Если BEGIN и END в одной строке
// (ключ в JSON-строке с \n), меняется середина. Если END нет — строка
// обрывается на BEGIN, и inPEM=true глушит следующие строки до END.
func replacePEM(line string, st *ruleStats) (string, bool) {
	if !strings.Contains(line, "-----BEGIN ") {
		return line, false
	}
	var b strings.Builder
	rest := line
	for {
		bm := rePEMBegin.FindStringIndex(rest)
		if bm == nil {
			b.WriteString(rest)
			return b.String(), false
		}
		b.WriteString(rest[:bm[1]])
		after := rest[bm[1]:]
		em := rePEMEnd.FindStringIndex(after)
		st.pem++
		b.WriteString(placeholderPEM)
		if em == nil {
			b.WriteString(line[bodyLen(line):])
			return b.String(), true
		}
		b.WriteString(after[em[0]:em[1]])
		rest = after[em[1]:]
	}
}

func pemTail(line string) (string, bool) {
	em := rePEMEnd.FindStringIndex(line)
	if em == nil {
		return "", true
	}
	return line[em[0]:], false
}

// applyRules — правила по одной строке, от самого точного. У регэкспов нет
// литерального префикса, и Go не умеет их быстро промотать: дешёвые Contains
// отсекают строки, где совпадения заведомо нет.
func applyRules(line string, st *ruleStats) (string, bool) {
	line, inPEM := replacePEM(line, st)
	hasQuote := strings.Contains(line, `"`)
	if hasQuote && strings.Contains(line, ":") {
		line = replaceFields(line, reJSONField, matchJSONField, st)
	}
	if hasQuote && strings.Contains(line, "=") {
		line = replaceFields(line, reQuotedEnv, matchQuotedEnv, st)
	}
	if strings.ContainsAny(line, "=:") {
		line = replaceFields(line, rePlainField, matchPlainField, st)
	}
	if strings.Contains(line, "://") {
		line = replaceURIPasswords(line, st)
	}
	return line, inPEM
}
