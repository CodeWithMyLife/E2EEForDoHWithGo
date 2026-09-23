package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	fastime "fastime/core"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfg, err := fastime.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	srv, err := fastime.NewServer(cfg)
	if err != nil {
		log.Fatal(err)
	}

	// 优雅退出：收到 SIGINT/SIGTERM 时关闭连接与监听
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		srv.Shutdown()
	}()

	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}
}
