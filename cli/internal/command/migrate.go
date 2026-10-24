package command

// sec migrate — перевод стора между форматами (протокол — store/migrate.go).
// Вывод — только счётчики и пути: ни значений, ни контрольных сумм.

import (
	"fmt"

	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/store"
)

func migrateCommand(args []string) int {
	fs := newFlagSet("migrate")
	var toV2 bool
	fs.BoolVar(&toV2, "to-v2", false, "вернуть стор в прежний формат SECSTOR2 (для отката на старый sec)")
	_ = fs.Parse(args)

	migrate := store.Migrate
	if toV2 {
		migrate = store.MigrateToV2
	}
	res, err := migrate()
	if err != nil {
		dieK(kindStore, "миграция не выполнена, стор прежний: %v", err)
	}
	out := map[string]any{"from": res.From, "to": res.To, "projects": res.Projects, "keys": res.Keys,
		"values": res.Values, "changed": res.From != res.To}
	if res.From == res.To {
		fmt.Fprintf(stdout, "стор уже в формате %s — менять нечего\n", res.To)
		emit(out)
		return 0
	}
	audit.Record("migrate", "*", res.From+" → "+res.To)
	fmt.Fprintf(stdout, "стор переведён %s → %s: проектов %d, ключей %d, значений с историей %d — сверено байт-в-байт\n",
		res.From, res.To, res.Projects, res.Keys, res.Values)
	if res.Backup != "" {
		out["backup"] = res.Backup
		fmt.Fprintf(stdout, "прежний файл сохранён: %s (зашифрован тем же мастер-ключом; удали, когда убедишься, что всё работает)\n", res.Backup)
	}
	if toV2 {
		fmt.Fprintln(stdout, "старый sec снова читает стор; вернуть SQLite — sec migrate")
	}
	emit(out)
	return 0
}
