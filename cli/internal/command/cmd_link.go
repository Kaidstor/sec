package command

// Ссылки на чужие значения и наследование пачек.
//
//	sec link <proj>/<KEY> <родитель>/<PKEY>   живая ссылка одного значения
//	sec unlink <proj>/<KEY>                    снять ссылку (значение станет своим)
//	sec extend <proj> --from <родитель>        видеть все ключи родителя read-only
//
// Значение по ссылке/наследованию нельзя менять в потомке (см. editBlock):
// правится в родителе, единый источник правды. Родитель без явного '@'
// наследует профиль потомка; свой профиль — parent@prod/KEY, базовый набор —
// parent@/KEY.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/store"

	"fmt"
)

func linkCommand(args []string) int {
	fs := newFlagSet("link")
	var force bool
	fs.BoolVar(&force, "force", false, "заменить существующее собственное значение ссылкой")
	pos := collectPositionals(fs, args)
	if len(pos) != 2 {
		die("нужно два аргумента: sec link <proj>/<KEY> <родитель>[@профиль]/<PKEY>")
	}
	cp, ck, profile := resolveRefP(pos[0])
	pp, pk := resolveRelRef(pos[1], profile)
	if cp == pp && ck == pk {
		die("нельзя ссылать ключ сам на себя")
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(true)
	if err != nil {
		dieStore(err)
	}
	if _, _, _, ok := st.Lookup(pp, pk); !ok {
		dieK(kindConflict, "родитель %s/%s не найден — сперва заведи его: sec set %s/%s", pp, pk, st.DisplayProj(pp), pk)
	}
	if cur, ok := st.Projects[cp][ck]; ok && cur.Ref == "" && !force {
		dieK(kindConflict, "%s/%s хранит собственное значение — sec link --force заменит его ссылкой (значение не сохранится)", cp, ck)
	}
	st.Project(cp)[ck] = store.Secret{Ref: pp + "/" + pk, UpdatedAt: store.Now()}
	if _, _, ok := st.ResolveSecret(cp, ck); !ok {
		dieK(kindConflict, "ссылка создала бы цикл — отклонено")
	}
	if err := store.Save(st, mkey); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record("link", cp+"/"+ck, "→ "+pp+"/"+pk)
	fmt.Fprintf(stdout, "%s/%s → ссылка на %s/%s (значение берётся из родителя, менять — там)\n", cp, ck, pp, pk)
	emit(map[string]any{"ref": cp + "/" + ck, "parent": pp + "/" + pk})
	return 0
}

func unlinkCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := newFlagSet("unlink")
	var drop bool
	fs.BoolVar(&drop, "drop", false, "удалить ключ вместо материализации значения родителя")
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, "sec unlink <proj>/<KEY>")

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	own, ok := st.Projects[proj][key]
	if !ok || own.Ref == "" {
		dieK(kindConflict, "%s/%s — не ссылка, отвязывать нечего", proj, key)
	}
	if drop {
		delete(st.Project(proj), key)
		st.Prune(proj)
		if err := store.Save(st, mkey); err != nil {
			dieK(kindStore, "запись хранилища: %v", err)
		}
		audit.Record("unlink", proj+"/"+key, "drop → "+own.Ref)
		fmt.Fprintf(stdout, "%s/%s: ссылка на %s удалена\n", proj, key, own.Ref)
		emit(map[string]any{"ref": proj + "/" + key, "parent": own.Ref, "dropped": true})
		return 0
	}
	sec, _, resolved := st.ResolveSecret(proj, key)
	if !resolved {
		dieK(kindConflict, "ссылка %s/%s → %s битая; удалить ключ: sec unlink %s --drop", proj, key, own.Ref, ref)
	}
	st.Project(proj)[key] = store.Secret{Value: sec.Value, Enc: sec.Enc, UpdatedAt: store.Now(), Meta: own.Meta}
	if err := store.Save(st, mkey); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record("unlink", proj+"/"+key, "материализовано из "+own.Ref)
	fmt.Fprintf(stdout, "%s/%s: отвязан от %s — теперь собственное значение (%d символов, скрыто)\n",
		proj, key, own.Ref, len([]rune(sec.Value)))
	emit(map[string]any{"ref": proj + "/" + key, "parent": own.Ref, "dropped": false, "chars": len([]rune(sec.Value))})
	return 0
}

func extendCommand(args []string) int {
	service, rest := splitArgs(args)
	fs := newFlagSet("extend")
	var from, remove string
	var list bool
	fs.StringVar(&from, "from", "", "родительская пачка (без '@' — профиль как у проекта; свой — parent@prod, базовый — parent@)")
	fs.StringVar(&remove, "remove", "", "убрать родительскую пачку из наследования")
	fs.BoolVar(&list, "list", false, "показать родителей проекта (по умолчанию, если без --from/--remove)")
	_ = fs.Parse(rest)
	if service == "" {
		service = fs.Arg(0)
	}
	proj, profile := resolveProjP(service)

	// без изменений — показать текущих родителей
	if from == "" && remove == "" {
		st, _, _, err := store.Open(false)
		if err != nil {
			dieStore(err)
		}
		parents := st.Extends[proj]
		type parentInfo struct {
			Project string `json:"project"`
			Keys    int    `json:"keys"`
		}
		list := []parentInfo{}
		for _, p := range parents {
			list = append(list, parentInfo{st.DisplayProj(p), len(st.Projects[p])})
		}
		emit(map[string]any{"project": proj, "parents": list})
		if len(parents) == 0 {
			fmt.Fprintf(stdout, "%s: наследования нет\n", proj)
			return 0
		}
		fmt.Fprintf(stdout, "%s наследует (read-only):\n", proj)
		for _, p := range list {
			fmt.Fprintf(stdout, "  %-24s %d ключ(ей)\n", p.Project, p.Keys)
		}
		return 0
	}
	if from != "" && remove != "" {
		die("--from и --remove вместе не имеют смысла")
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(true)
	if err != nil {
		dieStore(err)
	}

	if remove != "" {
		parent := resolveRelProj(remove, profile)
		if !st.RemoveExtend(proj, parent) {
			dieK(kindConflict, "%s не наследует от %s", proj, parent)
		}
		if err := store.Save(st, mkey); err != nil {
			dieK(kindStore, "запись хранилища: %v", err)
		}
		audit.Record("extend", proj, "− "+parent)
		fmt.Fprintf(stdout, "%s больше не наследует от %s\n", proj, parent)
		emit(map[string]any{"project": proj, "parent": parent, "removed": true})
		return 0
	}

	parent := resolveRelProj(from, profile)
	if len(st.Projects[parent]) == 0 && len(st.Extends[parent]) == 0 {
		dieK(kindConflict, "родительская пачка %q пуста или не существует (sec ls)", parent)
	}
	if !st.AddExtend(proj, parent) {
		dieK(kindConflict, "нельзя наследовать от %s — это создало бы цикл (или ссылку на себя)", parent)
	}
	if err := store.Save(st, mkey); err != nil {
		dieK(kindStore, "запись хранилища: %v", err)
	}
	audit.Record("extend", proj, "+ "+parent)
	fmt.Fprintf(stdout, "%s наследует ключи %s (read-only, свои ключи перекрывают)\n", proj, parent)
	emit(map[string]any{"project": proj, "parent": parent, "removed": false})
	return 0
}
