package command

// Ротация мастер-ключа: генерирует новый ключ и перешифровывает хранилище.
// Значения секретов сохраняются. Бэкенд ключа и стор одной транзакцией не
// записать, поэтому порядок такой, что сбой на любом шаге оставляет стор
// читаемым (подробно — keyring/pending.go):
//
//  1. новый ключ — в отдельный слот бэкенда (основной не тронут);
//  2. стор перешифровывается новым ключом одним коммитом;
//  3. новый ключ становится основным (env — печатается пользователю);
//  4. слот очищается.
//
// Упали после 2 — стор откроется ключом из слота, а первая же запись доведёт
// шаги 3–4.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/keyring"
	"github.com/kaidstor/sec/internal/store"

	"fmt"
	"io"
)

func rekeyCommand(args []string) int {
	fs := newFlagSet("rekey")
	_ = fs.Parse(args)

	st, _, backend, err := store.Begin(false)
	if err != nil {
		dieStore(err)
	}
	defer st.Close()
	catchSIGPIPE()

	// с бэкендом env новый ключ печатается один раз и больше нигде не живёт:
	// в конверт он не кладётся (секрет в JSON — только у get), а потерять его
	// значит потерять стор — отказываем до ротации
	if backend == "env" && jsonMode {
		return fail(2, kindUsage, "с мастер-ключом из SEC_KEY новый ключ печатается один раз — запусти sec rekey без --json")
	}
	if backend != "keyring" && backend != "file" && backend != "env" {
		dieK(kindConfig, "неизвестный бэкенд ключа %q", backend)
	}
	if backend == "env" {
		if stdoutDiscarded() {
			dieK(kindIO, "stdout закрыт или ведёт в /dev/null — новый мастер-ключ некуда напечатать; ротация не начата")
		}
	}
	envSlot := store.PendingKeyPath()
	slot := keyring.PendingLocation(backend, envSlot)
	if st.PendingKeyUsed() { // Begin не смог сделать ключ из слота основным (env — не может никогда)
		if backend == "env" {
			dieK(kindConflict, "стор зашифрован ключом из %s, а SEC_KEY старый — перенеси ключ в SEC_KEY и удали файл, потом rekey", slot)
		}
		dieK(kindConflict, "стор зашифрован ключом из %s, а основной слот не обновился — rekey отложен, чтобы не потерять этот ключ", slot)
	}
	// стор открылся основным ключом — значит, слот (если есть) остался от
	// rekey, упавшего до коммита, и ничего не защищает
	if err := keyring.ClearPending(backend, envSlot); err != nil {
		dieK(kindStore, "не удалось очистить %s: %v", slot, err)
	}

	newHex, newKey, err := keyring.NewHex()
	if err != nil {
		dieK(kindIO, "rand: %v", err)
	}
	if err := keyring.SavePending(backend, newHex, envSlot); err != nil {
		dieK(kindStore, "новый ключ не сохранён в %s, стор не тронут: %v", slot, err)
	}
	if err := st.RekeyTo(newKey); err != nil {
		dieK(kindStore, "%v", err)
	}
	if err := st.Commit(); err != nil {
		// слот не трогаем: если коммит всё же лёг на диск, стор откроется ключом из него
		dieK(kindStore, "перешифровка не удалась: %v (прежний ключ на месте; новый — в %s до следующего rekey)", err, slot)
	}
	if err := keyring.Promote(backend, newHex); err != nil {
		dieK(kindStore, "стор перешифрован, но новый ключ не стал основным: %v — он в %s, sec откроет стор им; повтори запись (sec rekey) позже", err, slot)
	}

	audit.Record("rekey", "*", "backend="+backend)
	committed = " — ротация мастер-ключа уже выполнена"
	if backend == "env" {
		// слот — единственная копия нового ключа, пока он не дошёл до stdout
		msg := "хранилище перешифровано. НОВЫЙ мастер-ключ — обнови SEC_KEY немедленно,\n" +
			"иначе на следующем запуске стор не расшифруется:\n" + newHex + "\n"
		if _, err := io.WriteString(checkedWriter{stdout}, msg); err != nil {
			return fail(2, kindIO, "новый мастер-ключ не выведен (%v): стор уже перешифрован, ключ сохранён в %s — перенеси его в SEC_KEY и удали файл", err, slot)
		}
	}
	if err := keyring.ClearPending(backend, envSlot); err != nil {
		warnf("ключ ротирован, но слот %s не очищен: %v", slot, err)
	}
	if backend == "env" {
		return 0
	}
	msg := fmt.Sprintf("мастер-ключ ротирован, хранилище перешифровано (бэкенд: %s)\n", backend) +
		"если делал переносной бэкап старым ключом — он по-прежнему открывается своей passphrase\n"
	if _, err := io.WriteString(checkedWriter{stdout}, msg); err != nil {
		return fail(2, kindIO, "вывод результата: %v%s", err, committed)
	}
	emit(map[string]any{"backend": backend})
	return 0
}
