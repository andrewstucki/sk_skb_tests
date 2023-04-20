package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/andrewstucki/sk_skb_tests/bpf"

	"github.com/cilium/ebpf/rlimit"
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	stop := make(chan os.Signal)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	errors := make(chan error, 1)
	go func() {
		errors <- bpf.Start(ctx)
	}()

	<-stop
	cancel()

	if err := <-errors; err != nil {
		log.Fatalf("error linking BPF program: %v", err)
	}
}
