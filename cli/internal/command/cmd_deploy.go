package command

// sec deploy — применить значения проекта к env-файлу: локальному или на хосте
// по ssh. Значения уходят на ту сторону через stdin ssh, в argv не попадают.
//
// По умолчанию merge, а не пересборка файла: прод-конфиг почти всегда содержит
// ключи, которых в сторе нет (их патчит CI, они заведены только на хосте), и
// пересборка их бы снесла. Пересобрать целиком просит явный --replace.

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/dotenv"
	"github.com/kaidstor/sec/internal/store"
)

func deployCommand(args []string) int {
	fs := newFlagSet("deploy")
	var to, only, after string
	var sudo, replace, noBackup, dryRun, yes bool
	fs.StringVar(&to, "to", "", "куда применить: [user@]host:/путь или локальный путь (обязателен)")
	fs.StringVar(&only, "only", "", "применить только перечисленные ключи (через запятую)")
	fs.StringVar(&after, "after", "", "команда на той стороне после записи, напр. 'cd /app && docker compose up svc -d'")
	fs.BoolVar(&sudo, "sudo", false, "читать/писать под sudo (root-овые прод-конфиги)")
	fs.BoolVar(&replace, "replace", false, "пересобрать файл целиком: ключи, которых нет в сторе, будут удалены")
	fs.BoolVar(&noBackup, "no-backup", false, "не делать <путь>.bak-<время> перед записью")
	fs.BoolVar(&dryRun, "dry-run", false, "показать, что изменится, и выйти без записи")
	fs.BoolVar(&yes, "yes", false, "не спрашивать подтверждения (CI)")
	// collectPositionals, а не splitArgs: иначе `sec deploy --sudo whois --to …`
	// останавливает разбор флагов на `whois`, и --to молча теряется.
	pos := collectPositionals(fs, args)
	if len(pos) > 1 {
		die("лишний аргумент %q: sec deploy [proj] --to <host>:/путь", pos[1])
	}
	service := ""
	if len(pos) > 0 {
		service = pos[0]
	}
	proj, _ := resolveServiceProj(service, fs)

	if to == "" {
		die("укажи цель: sec deploy %s --to <host>:/app/.env", proj)
	}
	t, err := parseEnvTarget(to)
	if err != nil {
		die("--to: %v", err)
	}
	// Вместе они означают взаимоисключающее: «файл = стор целиком» и «трогаем
	// только эти ключи». Раньше побеждал --only, и файл пересобирался из его
	// подмножества — то есть остальные ключи молча исчезали, причём diff их
	// удаление не показывал (они отфильтрованы из сравнения тем же --only).
	if replace && only != "" {
		die("--replace и --only несовместимы: --replace пересобирает файл целиком из стора,\n" +
			"     а --only оставил бы в нём только перечисленные ключи (остальные исчезли бы молча)")
	}

	st, mkey, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	keys := envKeysOf(st, proj, only)

	data, exists, err := t.read(sudo)
	if err != nil {
		dieK(targetKind(t), "чтение %s: %v", t, err)
	}
	if !exists {
		warnf("%s ещё нет — файл будет создан с правами 0600", t)
	}
	if ml := dotenv.MultilineKeys(string(data)); len(ml) > 0 {
		dieK(kindConflict, "в %s есть многострочные значения (%s) — построчный merge порвал бы их пополам.\n"+
			"     Такой файл править руками; многострочному секрету в .env не место (sec get %s/<KEY> --out <файл>)",
			t, strings.Join(ml, ", "), st.DisplayProj(proj))
	}
	fileKV := parseEnvTargetFile(t, data)
	if only != "" { // ключи вне --only не наши: в отчёт как «только на хосте» им нельзя
		for k := range fileKV {
			if _, ok := keys[k]; !ok {
				delete(fileKV, k)
			}
		}
	}

	entries := compareEnvFile(keys, fileKV, mkey)
	c := printEnvDiff(entries, t, replace)
	needWrite := c.changed() || (replace && c.extra > 0)
	res := map[string]any{"project": proj, "target": t.String(), "keys": envEntriesJSON(entries, replace),
		"counts": c.json(), "written": []string{}, "dryRun": dryRun}
	emit(res)
	if !needWrite {
		fmt.Fprintln(stdout, "нечего делать — файл уже соответствует стору")
		if after != "" { // рестарт — следствие записи; молча «выполнено» тут было бы враньём
			warnf("--after не выполнялся (записи не было) — если сервис надо перезапустить, сделай это отдельно")
		}
		return 0
	}
	if dryRun {
		if !jsonMode { // в JSON это поле dryRun
			warnf("--dry-run — ничего не записано")
		}
		return 0
	}

	if replace && c.extra > 0 {
		warnf("--replace: %s потеряет %d ключ(ей), которых нет в сторе", t, c.extra)
	}
	if !yes {
		what := fmt.Sprintf("применить %d ключ(ей) к %s", c.differ+c.missing, t)
		if replace {
			what = fmt.Sprintf("пересобрать %s из стора", t)
		}
		if !confirmYes(what + "?") {
			return fail(1, kindCancelled, "отменено")
		}
	}

	out, written := buildEnvFile(proj, string(data), keys, entries, replace)

	// Между первым чтением и этой точкой прошли показ diff, подтверждение и
	// (при --sudo) ввод пароля — за это время файл мог поменять CI или человек.
	// Записать собранное из старого снимка значит молча снести их правку, и
	// verify этого не заметит: он сверяет только наши ключи.
	if fresh, _, rerr := t.read(sudo); rerr == nil && !bytes.Equal(fresh, data) {
		dieK(kindConflict, "%s изменился, пока шло подтверждение — ничего не записано, перезапусти sec deploy", t)
	}

	bak := ""
	if exists && !noBackup {
		// миллисекунды в имени не для красоты: два деплоя в одну секунду
		// перезаписали бы бэкап друг друга — ровно тот, ради которого всё и затевалось
		bak = t.path + ".bak-" + time.Now().Format("20060102-150405.000")
		if err := t.backup(sudo, bak); err != nil {
			dieK(targetKind(t), "бэкап %s: %v", bak, err)
		}
		fmt.Fprintf(stdout, "бэкап: %s\n", bak)
		res["backup"] = bak
	}
	if err := t.write(sudo, []byte(out)); err != nil {
		dieK(targetKind(t), "запись %s: %v", t, err)
	}
	audit.Record("deploy", proj, fmt.Sprintf("→ %s (%d ключ(ей))", t, len(written)))
	fmt.Fprintf(stdout, "записан %s: %s\n", t, strings.Join(written, ", "))
	res["written"] = written

	// Verify до --after, а не после: перезапускать сервис на файле, который не
	// сошёлся с отпечатками, нельзя — так падение будет тихим и уже в проде.
	if code := verifyDeployed(t, sudo, keys, written, mkey, bak); code != 0 {
		return code
	}
	res["verified"] = true
	if after != "" {
		fmt.Fprintf(stdout, "выполняю на %s: %s\n", targetWhere(t), after)
		if err := t.after(after); err != nil {
			dieK(targetKind(t), "--after: %v", err)
		}
		res["after"] = after
	}
	return 0
}

// buildEnvFile собирает новое содержимое файла: merge вписывает изменившиеся и
// недостающие ключи в исходный текст (порядок строк и комментарии остаются),
// --replace пересобирает файл из стора целиком. Второй результат — какие ключи
// реально записаны.
func buildEnvFile(proj, orig string, keys map[string]store.Secret, entries []envEntry, replace bool) (string, []string) {
	if replace {
		var b strings.Builder
		fmt.Fprintf(&b, "# сгенерировано sec из проекта %s — не коммитить\n", proj)
		names := store.SortedKeys(keys)
		for _, k := range names {
			b.WriteString(dotenv.Line(k, keys[k].Value) + "\n")
		}
		return b.String(), names
	}
	kv := map[string]string{}
	for _, e := range entries {
		if e.status == envDiffer || e.status == envMissing {
			kv[e.key] = keys[e.key].Value
		}
	}
	out, updated, added := dotenv.Merge(orig, kv)
	return out, sortedUnion(updated, added)
}

// verifyDeployed перечитывает файл и сверяет отпечатки записанных ключей —
// подтверждение, что применилось именно то, что собирались применить (ssh мог
// оборваться на середине, sudo — записать не туда).
func verifyDeployed(t envTarget, sudo bool, keys map[string]store.Secret, written []string, mkey []byte, bak string) int {
	data, exists, err := t.read(sudo)
	if err != nil {
		return fail(2, targetKind(t), "не удалось перечитать %s для сверки: %v", t, err)
	}
	if !exists {
		return fail(2, targetKind(t), "после записи %s не читается — проверь вручную", t)
	}
	after, _ := dotenv.Parse(string(data))
	var bad []string
	for _, k := range written {
		if store.Fingerprint(mkey, after[k]) != store.Fingerprint(mkey, keys[k].Value) {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		where := "бэкапа нет (--no-backup)"
		if bak != "" {
			where = "откатить: " + bak
		}
		return fail(2, kindConflict, "после записи не сошлись отпечатки: %s (%s)", strings.Join(bad, ", "), where)
	}
	fmt.Fprintf(stdout, "сверено после записи: применилось %d ключ(ей)\n", len(written))
	return 0
}

// targetWhere — «на whois» / «локально» для сообщения про --after.
func targetWhere(t envTarget) string {
	if t.remote() {
		return t.host
	}
	return "этой машине"
}

// sortedUnion объединяет два набора имён в один отсортированный без дублей.
func sortedUnion(a, b []string) []string {
	set := map[string]struct{}{}
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		set[s] = struct{}{}
	}
	return store.SortedKeys(set)
}
