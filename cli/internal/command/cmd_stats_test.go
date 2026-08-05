package command

import (
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/stats"
)

// В счётчик попадают только объявленные флаги команды — это не косметика, а
// гарантия, что туда не утечёт ничего, набранного пользователем свободно.
func TestUsedFlagsWhitelistsKnownOnly(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
		want string
	}{
		{"get", []string{"proj/KEY", "--peek"}, "--peek"},
		{"get", []string{"--clip", "--peek", "--clip"}, "--clip,--peek"},               // дубли схлопываются
		{"share", []string{"proj/KEY", "--ttl=3d"}, "--ttl"},                           // значение через = отрезается
		{"get", []string{"-peek"}, "--peek"},                                           // одиночный дефис — то же написание
		{"set", []string{"proj/KEY", "--note", "-черновик, потом перепишу"}, "--note"}, // значение флага не попадает
		{"run", []string{"proj", "--", "just", "dev", "--watch"}, ""},                  // флаги чужой команды не наши
		{"get", []string{"--несуществующий", "--peek"}, "--peek"},                      // опечатки отбрасываются
		{"get", []string{"-e", "prod"}, "-e"},                                          // короткая форма живёт отдельно от --env
		{"version", []string{"--json"}, ""},                                            // у команды нет флагов — нечего писать
	}
	for _, c := range cases {
		if got := strings.Join(usedFlags(c.cmd, c.args), ","); got != c.want {
			t.Errorf("usedFlags(%q, %v) = %q, ожидалось %q", c.cmd, c.args, got, c.want)
		}
	}
}

func TestNeverUsed(t *testing.T) {
	u := &stats.File{Keys: map[string]*stats.Counter{
		"get":        {N: 5},
		"get --peek": {N: 3},
	}}
	cmds, flags := neverUsed(u)

	if contains(cmds, "get") {
		t.Error("запускавшаяся команда не должна попадать в «ни разу»")
	}
	if !contains(cmds, "backup") {
		t.Error("незапускавшаяся команда должна попадать в «ни разу»")
	}
	if contains(flags, "get --peek") {
		t.Error("использованный флаг не должен попадать в «ни разу»")
	}
	if !contains(flags, "get --clip") {
		t.Error("неиспользованный флаг живой команды должен попадать в «ни разу»")
	}
	// у команды, которую не открывали, флаги не перечисляем — это шум, а не находка
	for _, f := range flags {
		if strings.HasPrefix(f, "backup ") {
			t.Errorf("флаги незапускавшейся команды перечислять не надо: %s", f)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
