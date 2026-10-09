package command

import (
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

func redactRules(t *testing.T, st *store.Store, in string, rules bool) (string, *redactor) {
	t.Helper()
	if st == nil {
		st = &store.Store{Version: 1, Projects: map[string]map[string]store.Secret{}}
	}
	return runRedactor(t, st, in, storeScope{minLen: 8}, false, rules)
}

func TestRedactRulesCaseRepro(t *testing.T) {
	in := `{"BOT_TOKEN":"example-not-a-real-bot-token","DATABASE_URL":"postgresql://example:example-not-a-real-password@db.invalid:5432/example"}` + "\n"
	out, rd := redactRules(t, nil, in, true)
	want := `{"BOT_TOKEN":"[redacted:field]","DATABASE_URL":"postgresql://example:[redacted:uri]@db.invalid:5432/example"}` + "\n"
	if out != want {
		t.Fatalf("\n got %s\nwant %s", out, want)
	}
	if rd.stats.fields["BOT_TOKEN"] != 1 || rd.stats.uri != 1 || rd.stats.total() != 2 {
		t.Errorf("статистика правил: %+v", rd.stats)
	}
}

func TestRedactRulesStoreOnlyKeepsOldBehaviour(t *testing.T) {
	in := `{"BOT_TOKEN":"example-not-a-real-bot-token"}`
	out, rd := redactRules(t, nil, in, false)
	if out != in || rd.stats.total() != 0 {
		t.Errorf("--store-only не должен применять правила: %q", out)
	}
}

func TestRedactRulesMixedStoreAndUnknown(t *testing.T) {
	// Известное значение — под своим именем, неизвестное — правилом; сигнал
	// «скрыто из стора» не должен глушить находку правил.
	st := &store.Store{Version: 1, Projects: map[string]map[string]store.Secret{
		"proxy": {"PASSWORD": {Value: "known-proxy-password"}},
	}}
	in := `{"PROXY_PASSWORD":"known-proxy-password","POSTGRES_PASSWORD":"unknown-pg-password-x"}` + "\n"
	out, rd := redactRules(t, st, in, true)
	if strings.Contains(out, "known-proxy-password") || strings.Contains(out, "unknown-pg-password-x") {
		t.Fatalf("значение утекло: %q", out)
	}
	if !strings.Contains(out, `"PROXY_PASSWORD":"[redacted:proxy/PASSWORD]"`) {
		t.Errorf("значение стора должно скрыться под своим именем: %q", out)
	}
	if !rd.hit["proxy/PASSWORD"] || rd.stats.fields["POSTGRES_PASSWORD"] != 1 {
		t.Errorf("hit=%v stats=%+v", rd.hit, rd.stats)
	}
	if _, ok := rd.stats.fields["PROXY_PASSWORD"]; ok {
		t.Errorf("поле, скрытое стором, не должно считаться находкой правил")
	}
}

func TestRedactRulesFieldForms(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"compose env array", `"Env":["BOT_TOKEN=synthetic-bot-token","TZ=Europe/Moscow"]`, `"Env":["BOT_TOKEN=[redacted:field]","TZ=Europe/Moscow"]`},
		{"env with spaces in quotes", `["PASSWORD=a b c"]`, `["PASSWORD=[redacted:field]"]`},
		{"dotenv", "POSTGRES_PASSWORD=synthetic-pg-pass\n", "POSTGRES_PASSWORD=[redacted:field]\n"},
		{"export quoted", `export API_KEY="synthetic key"`, `export API_KEY="[redacted:field]"`},
		{"yaml", "  password: synthetic-yaml-pass\n", "  password: [redacted:field]\n"},
		{"compose list", "      - JWT_SECRET=synthetic-jwt\n", "      - JWT_SECRET=[redacted:field]\n"},
		{"log line keeps rest", "msg=login token=synthetic-tok user=bob", "msg=login token=[redacted:field] user=bob"},
		{"cli flag", "psql --password=synthetic-flag-pw -h db", "psql --password=[redacted:field] -h db"},
		{"query param", "GET /cb?code=1&access_token=synthetic-at&x=2", "GET /cb?code=1&access_token=[redacted:field]&x=2"},
		{"header", "Authorization: Bearer synthetic-bearer", "Authorization: [redacted:field]"},
		{"camelCase json", `{"clientSecret": "synthetic-cs", "apiKey":"synthetic-ak"}`, `{"clientSecret": "[redacted:field]", "apiKey":"[redacted:field]"}`},
		{"escaped quote in value", `{"PASSWORD":"syn\"thetic"}`, `{"PASSWORD":"[redacted:field]"}`},
		{"json inside json string", `{"body":"{\"BOT_TOKEN\":\"synthetic-nested\",\"ok\":1}"}`, `{"body":"{\"BOT_TOKEN\":\"[redacted:field]\",\"ok\":1}"}`},
		{"vault secret_id", `{"secret_id":"synthetic-sid"}`, `{"secret_id":"[redacted:field]"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _ := redactRules(t, nil, c.in, true)
			if out != c.want {
				t.Errorf("\n got %s\nwant %s", out, c.want)
			}
		})
	}
}

func TestRedactRulesNoFalsePositives(t *testing.T) {
	cases := []string{
		`{"POSTGRES_PASSWORD_FILE":"/run/secrets/pg"}`,
		`TOKEN_URL=https://auth.example.invalid/token`,
		`PASSWORD_MIN_LENGTH=12`,
		`AUTH_ENABLED=true`,
		`{"max_tokens": 4096}`,
		`{"key":"theme","value":"dark"}`,
		`BOT_TOKEN=${BOT_TOKEN}`,
		`api_key: {{ secret "app/API_KEY" }}`,
		`PASSWORD=`,
		`password: <your-password>`,
		`DATABASE_URL=postgresql://example@db.invalid:5432/example`,
		`see http://[::1]:8080/path and https://host.invalid:443/a?b=c`,
		`PUBLIC_KEY=ssh-ed25519 AAAAsynthetic`,
	}
	for _, in := range cases {
		out, rd := redactRules(t, nil, in, true)
		if out != in || rd.stats.total() != 0 {
			t.Errorf("ложное срабатывание:\n in %s\nout %s", in, out)
		}
	}
}

func TestRedactRulesURI(t *testing.T) {
	cases := []struct{ in, want string }{
		{"redis://:synthetic-redis@cache.invalid:6379/0", "redis://:[redacted:uri]@cache.invalid:6379/0"},
		{"postgres://u:p%40ss%3Aw0rd@db.invalid/x", "postgres://u:[redacted:uri]@db.invalid/x"},
		{"amqp://u:raw@pass@mq.invalid/vh", "amqp://u:[redacted:uri]@mq.invalid/vh"},
		{"http://user:pw1@[2001:db8::1]:8080/p", "http://user:[redacted:uri]@[2001:db8::1]:8080/p"},
		{"a=https://x:one@h1.invalid b=https://y:two@h2.invalid", "a=https://x:[redacted:uri]@h1.invalid b=https://y:[redacted:uri]@h2.invalid"},
	}
	for _, c := range cases {
		out, _ := redactRules(t, nil, c.in, true)
		if out != c.want {
			t.Errorf("\n got %s\nwant %s", out, c.want)
		}
	}
}

func TestRedactRulesPEMMultiline(t *testing.T) {
	in := "before\n-----BEGIN RSA PRIVATE KEY-----\nc3ludGhldGljLWJvZHktMQ==\nc3ludGhldGljLWJvZHktMg==\n-----END RSA PRIVATE KEY-----\nafter token=synthetic-after\n"
	out, rd := redactRules(t, nil, in, true)
	want := "before\n-----BEGIN RSA PRIVATE KEY-----[redacted:pem]\n-----END RSA PRIVATE KEY-----\nafter token=[redacted:field]\n"
	if out != want {
		t.Fatalf("\n got %q\nwant %q", out, want)
	}
	if rd.stats.pem != 1 {
		t.Errorf("pem=%d", rd.stats.pem)
	}
}

func TestRedactRulesPEMInJSONString(t *testing.T) {
	in := `{"cert":"-----BEGIN PRIVATE KEY-----\nc3ludGhldGlj\n-----END PRIVATE KEY-----\n","x":1}`
	out, _ := redactRules(t, nil, in, true)
	want := `{"cert":"-----BEGIN PRIVATE KEY-----[redacted:pem]-----END PRIVATE KEY-----\n","x":1}`
	if out != want {
		t.Errorf("\n got %s\nwant %s", out, want)
	}
}

func TestRedactRulesPEMUnterminatedSwallowsRest(t *testing.T) {
	// END так и не пришёл — безопаснее проглотить хвост, чем выпустить тело ключа.
	in := "-----BEGIN OPENSSH PRIVATE KEY-----\nc3ludGhldGlj\nmore\n"
	out, _ := redactRules(t, nil, in, true)
	if out != "-----BEGIN OPENSSH PRIVATE KEY-----[redacted:pem]\n" {
		t.Errorf("got %q", out)
	}
}

func TestSensitiveKey(t *testing.T) {
	yes := []string{"BOT_TOKEN", "VAULT_TOKEN", "PASSWORD", "POSTGRES_PASSWORD", "DB_PASS", "JWT_SECRET",
		"PRIVATE_KEY", "privateKey", "apiKey", "X-Api-Key", "SECRET_KEY_BASE", "client_secret", "SENTRY_DSN",
		"Authorization", "Cookie", "secret_id", "ENCRYPTION_KEY"}
	no := []string{"DATABASE_URL", "PASSWORD_FILE", "TOKEN_URL", "PASSWORD_MIN_LENGTH", "key", "PUBLIC_KEY",
		"KEY_ID", "USERNAME", "TOKENIZER", "COOKIE_DOMAIN", "AUTH_ENABLED", "SECRET_NAME"}
	for _, k := range yes {
		if !sensitiveKey(k) {
			t.Errorf("%s должен считаться секретным", k)
		}
	}
	for _, k := range no {
		if sensitiveKey(k) {
			t.Errorf("%s не должен считаться секретным", k)
		}
	}
}
