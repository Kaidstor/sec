package command

// Вывод команд. По умолчанию — текст для человека; --json в любом месте argv
// (до «--») переключает любую команду на конверт семьи CLI (скилл kai-cli):
//
//	{"v": 1, "command": "get", "exit": 0, "data": {…}, "warning": ["…"], "error": null}
//
// Команды печатают текст в stdout (переменная пакета, не os.Stdout) и отдают
// данные для JSON через emit. В JSON-режиме текст уходит в буфер: если команда
// данных не отдала, буфер становится data.text — конверт есть у любой команды.
// Отказ (die/fail) в JSON-режиме — тем же конвертом в stdout с error{kind,
// message}, в тексте — строкой «sec: …» в stderr.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const schemaVersion = 1

// Классы ошибок (error.kind). Общие для семьи CLI — usage, auth, network,
// not_found, api; остальные — предметные у sec.
const (
	kindUsage       = "usage"       // аргументы, флаги, неверный адрес или имя
	kindNotFound    = "not_found"   // нет ключа или проекта (код 3)
	kindConfig      = "config"      // не настроено: сервер ссылок, бэкенд мастер-ключа
	kindStore       = "store"       // хранилище или мастер-ключ не открылись / не записались
	kindConflict    = "conflict"    // состояние не даёт: ссылка/наследование read-only, ключ уже есть, цикл
	kindIO          = "io"          // файл, stdin, буфер обмена, TTY
	kindNetwork     = "network"     // share-сервер или ssh-хост недоступны
	kindAuth        = "auth"        // share-сервер не принял токен, не подошла passphrase
	kindAPI         = "api"         // share-сервер или Infisical ответили ошибкой
	kindCancelled   = "cancelled"   // пользователь не подтвердил действие (код 1)
	kindInterrupted = "interrupted" // Ctrl+C во время ввода (код 130)
)

type failure struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type envelope struct {
	V       int      `json:"v"`
	Command string   `json:"command"`
	Exit    int      `json:"exit"`
	Data    any      `json:"data"`
	Warning []string `json:"warning,omitempty"`
	Error   *failure `json:"error"`
}

var (
	jsonMode   bool
	curCommand string

	// stdout — куда команды печатают текстовый результат. В JSON-режиме это
	// буфер: в настоящий stdout попадает только конверт.
	stdout     io.Writer = os.Stdout
	realStdout io.Writer = os.Stdout
	captured   bytes.Buffer

	resultData any
	resultSet  bool
	pending    *failure
	warnings   []string
)

// splitGlobalFlags вынимает --json/--human из любого места argv до «--»
// (дальше — аргументы чужой команды: sec run -- tool --json). Последний
// из двух побеждает.
func splitGlobalFlags(args []string) (bool, []string) {
	asJSON := false
	out := make([]string, 0, len(args))
	for i, a := range args {
		if a == "--" {
			out = append(out, args[i:]...)
			break
		}
		switch a {
		case "--json", "-json":
			asJSON = true
		case "--human", "-human":
			asJSON = false
		default:
			out = append(out, a)
		}
	}
	return asJSON, out
}

// startOutput включает режим вывода для команды cmd.
func startOutput(cmd string, asJSON bool) {
	curCommand, jsonMode = cmd, asJSON
	captured.Reset()
	resultData, resultSet, pending, warnings = nil, false, nil, nil
	if asJSON {
		stdout = &captured
	} else {
		stdout = realStdout
	}
}

// emit отдаёт данные команды для JSON-конверта. В текстовом режиме ничего не
// делает — текст команда печатает сама.
func emit(data any) {
	resultData, resultSet = data, true
}

// warnf — предупреждение: в тексте строкой «sec: …» в stderr, в JSON — в
// поле warning. Код выхода не меняет.
func warnf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if jsonMode {
		warnings = append(warnings, msg)
		return
	}
	fmt.Fprintln(os.Stderr, "sec: "+msg)
}

// fail фиксирует отказ и возвращает код для return из команды.
func fail(code int, kind, format string, a ...any) int {
	msg := fmt.Sprintf(format, a...)
	if jsonMode {
		pending = &failure{Kind: kind, Message: msg}
		return code
	}
	fmt.Fprintln(os.Stderr, "sec: "+msg)
	return code
}

// finish печатает конверт (в JSON-режиме) и возвращает код.
func finish(code int) int {
	if !jsonMode {
		return code
	}
	env := envelope{V: schemaVersion, Command: curCommand, Exit: code, Warning: warnings, Error: pending}
	switch {
	case pending != nil:
	case resultSet:
		env.Data = resultData
	case captured.Len() > 0:
		env.Data = map[string]string{"text": strings.TrimRight(captured.String(), "\n")}
	}
	enc := json.NewEncoder(realStdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // иначе & в share-ссылках уезжает в &
	_ = enc.Encode(env)
	return code
}

// exitNow завершает процесс с конвертом — для отказов из глубины хелперов.
func exitNow(code int) {
	os.Exit(finish(code))
}

func die(format string, a ...any) {
	exitNow(fail(2, kindUsage, format, a...))
}

// dieK — отказ с кодом 2 и заданным классом.
func dieK(kind, format string, a ...any) {
	exitNow(fail(2, kind, format, a...))
}

// dieStore — хранилище не открылось или не записалось.
func dieStore(err error) {
	dieK(kindStore, "%v", err)
}

// dieNotFound — «адресата нет» (ключ/проект): отдельный код выхода 3, чтобы
// обёртки (GUI, secretspec-провайдер) отличали отсутствие секрета от настоящей
// ошибки (нечитаемый стор, битая ссылка) без разбора русских сообщений.
func dieNotFound(format string, a ...any) {
	exitNow(fail(3, kindNotFound, format, a...))
}

// interrupted — Ctrl+C во время скрытого ввода: код 130, как у шелла.
func interrupted() {
	exitNow(fail(130, kindInterrupted, "прервано"))
}

// childStdout — куда отдавать вывод дочерних команд (deploy --after): в
// JSON-режиме stdout занят конвертом, поток ребёнка уходит в stderr.
func childStdout() io.Writer {
	if jsonMode {
		return os.Stderr
	}
	return os.Stdout
}

// newFlagSet — FlagSet команды. Ошибка разбора флагов в JSON-режиме уходит
// конвертом (kind usage, код 2), -h — конвертом со справкой флагов (код 0);
// в тексте — как у пакета flag.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	if !jsonMode {
		return fs
	}
	var errBuf bytes.Buffer
	fs.SetOutput(&errBuf)
	fs.Usage = func() {
		// flag печатает текст ошибки в Output до вызова Usage; у -h текста нет
		msg := strings.TrimSpace(errBuf.String())
		if msg != "" {
			exitNow(fail(2, kindUsage, "%s (sec %s -h — флаги команды)", msg, name))
		}
		var help bytes.Buffer
		fs.SetOutput(&help)
		fs.PrintDefaults()
		emit(map[string]string{"flags": strings.TrimRight(help.String(), "\n")})
		exitNow(0)
	}
	return fs
}
