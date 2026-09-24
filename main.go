package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	fastime "fastime/core"
)

// fatal 同时把错误写进 stderr 和 fastime.log，再退出。
// 配置加载失败发生在文件日志器初始化之前，
// 若不写文件，Windows 双击运行时窗口一闪而过，错误无处可查。
// 日志位置：当前目录 → 失败则回退用户主目录（macOS .app 的 cwd 是 / 不可写）。
func fatal(err error) {
	msg := "[FATAL] " + err.Error()
	log.Println(msg)
	line := fmt.Sprintf("%s %s\n", time.Now().Format("15:04:05.000000"), msg)
	if f, ferr := os.OpenFile("fastime.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); ferr == nil {
		f.WriteString(line)
		f.Close()
	} else if home, herr := os.UserHomeDir(); herr == nil {
		if f, ferr2 := os.OpenFile(filepath.Join(home, "fastime.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); ferr2 == nil {
			f.WriteString(line)
			f.Close()
		}
	}
	os.Exit(1)
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfg, err := fastime.LoadConfig()
	if err != nil {
		fatal(err)
	}
	srv, err := fastime.NewServer(cfg)
	if err != nil {
		fatal(err)
	}

	// 优雅退出：收到 SIGINT/SIGTERM 时关闭连接与监听
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		srv.Shutdown()
	}()

	if err := srv.Start(); err != nil {
		fatal(err)
	}
}
