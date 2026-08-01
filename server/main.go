// sec-share — сервер одноразовых зашифрованных ссылок для sec CLI.
// Хранит только шифроблобы: ключ расшифровки живёт в URL-фрагменте и сюда не
// попадает. Конфиг — переменные окружения SEC_SHARE_* (см. serverUsage).
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var version = "dev"

const serverUsage = `sec-share — сервер одноразовых зашифрованных ссылок.

  sec-share [serve]            запустить сервер
  sec-share token add <имя>    выпустить токен создателя (печатается один раз)
  sec-share token ls           список токенов (имена и даты, без значений)
  sec-share token rm <имя>     отозвать токен
  sec-share version            версия

Окружение:
  SEC_SHARE_ADDR        адрес прослушивания (умолч. :8080)
  SEC_SHARE_DATA        каталог данных (умолч. /data)
  SEC_SHARE_MAX_BLOB    лимит блоба в байтах (умолч. 8388608)
  SEC_SHARE_MAX_TTL     максимальный TTL (умолч. 168h)
  SEC_SHARE_REAP_EVERY  период чистки протухших (умолч. 1m)
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "serve":
		return serve()
	case "token":
		return tokenCommand(args[1:])
	case "version", "-v", "--version":
		fmt.Println("sec-share", version)
		return 0
	case "-h", "--help", "help":
		fmt.Print(serverUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "sec-share: неизвестная команда %q\n\n%s", cmd, serverUsage)
		return 2
	}
}

func envStr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envInt64(name string, def int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		fmt.Fprintf(os.Stderr, "sec-share: %s=%q — не положительное число, беру %d\n", name, v, def)
		return def
	}
	return n
}

func envDur(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		fmt.Fprintf(os.Stderr, "sec-share: %s=%q — не длительность, беру %s\n", name, v, def)
		return def
	}
	return d
}

func serve() int {
	addr := envStr("SEC_SHARE_ADDR", ":8080")
	dataDir := envStr("SEC_SHARE_DATA", "/data")

	st, err := NewStorage(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sec-share: %v\n", err)
		return 1
	}
	stop := make(chan struct{})
	st.StartReaper(envDur("SEC_SHARE_REAP_EVERY", time.Minute), stop)

	srv := NewServer(st, NewTokenFile(dataDir),
		envInt64("SEC_SHARE_MAX_BLOB", 8<<20),
		envDur("SEC_SHARE_MAX_TTL", 168*time.Hour))
	hs := &http.Server{
		Addr:              addr,
		Handler:           srv.Mux(),
		ReadHeaderTimeout: 10 * time.Second,
		// таймауты с запасом на аплоад/выдачу 8-МиБ блоба по медленному каналу
		ReadTimeout:  2 * time.Minute,
		WriteTimeout: 2 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	shutdownDone := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
		close(shutdownDone)
	}()

	fmt.Printf("sec-share %s: слушаю %s, данные в %s\n", version, addr, dataDir)
	err = hs.ListenAndServe()
	if err == http.ErrServerClosed {
		// дождаться дренажа соединений: выход из main до конца Shutdown обрывал
		// бы in-flight claim уже после сжигания once-ссылки
		<-shutdownDone
		return 0
	}
	fmt.Fprintf(os.Stderr, "sec-share: %v\n", err)
	return 1
}

func tokenCommand(args []string) int {
	dataDir := envStr("SEC_SHARE_DATA", "/data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "sec-share: %v\n", err)
		return 1
	}
	tf := NewTokenFile(dataDir)
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "sec-share: укажи имя: token add <имя>")
			return 2
		}
		token, err := tf.Issue(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "sec-share: %v\n", err)
			return 1
		}
		fmt.Println(token)
		fmt.Fprintln(os.Stderr, "токен показан один раз, в файле остаётся только хэш — подключай: sec share setup <url>")
		return 0
	case "ls":
		entries, err := tf.List()
		if err != nil {
			fmt.Fprintf(os.Stderr, "sec-share: %v\n", err)
			return 1
		}
		if len(entries) == 0 {
			fmt.Println("токенов нет (выпустить: token add <имя>)")
			return 0
		}
		for _, e := range entries {
			fmt.Printf("%s\t%s\n", e.Name, e.CreatedAt)
		}
		return 0
	case "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "sec-share: укажи имя: token rm <имя>")
			return 2
		}
		if err := tf.Remove(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "sec-share: %v\n", err)
			return 1
		}
		fmt.Printf("токен %s отозван\n", args[1])
		return 0
	default:
		fmt.Fprintf(os.Stderr, "sec-share: token add|ls|rm <имя>\n")
		return 2
	}
}
