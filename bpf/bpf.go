package bpf

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func freePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

//go:generate bpf2go -strip $BPF_STRIP -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf bpf.c -- -I./headers

func Start(ctx context.Context) (ret error) {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return err
	}

	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.SockMap.FD(),
		Program: objs.Verdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	}); err != nil {
		return err
	}

	defer func() {
		if err := link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  objs.SockMap.FD(),
			Program: objs.Verdict,
			Attach:  ebpf.AttachSkSKBStreamVerdict,
		}); err != nil {
			ret = err
		}
	}()

	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.SockMap.FD(),
		Program: objs.Parser,
		Attach:  ebpf.AttachSkSKBStreamParser,
	}); err != nil {
		return err
	}

	defer func() {
		if err := link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  objs.SockMap.FD(),
			Program: objs.Parser,
			Attach:  ebpf.AttachSkSKBStreamParser,
		}); err != nil {
			ret = err
		}
	}()

	port, err := freePort()
	if err != nil {
		return err
	}

	go runTCPClient(ctx, port)

	return runTCPServer(ctx, &objs, port)
}

func runTCPClient(ctx context.Context, port int) {
	var conn net.Conn
	var err error

DIAL:
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				continue
			}
			break DIAL
		}
	}

	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Second):
			fmt.Fprintf(conn, "hi\n")
		}
	}
}

func runTCPServer(ctx context.Context, objs *bpfObjects, port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConn(ctx, conn, objs)
		}
	}()

	<-ctx.Done()

	return nil
}

func handleConn(ctx context.Context, conn net.Conn, objs *bpfObjects) {
	defer conn.Close()

	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		fmt.Println("error getting socket fd", err)
		return
	}
	fd := file.Fd()

	key := 0
	if err := objs.SockMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&fd), ebpf.UpdateAny); err != nil {
		fmt.Println("error adding socket", err)
		return
	}

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("error reading", err)
			return
		}
		fmt.Printf("incoming data: %s", line)
	}
}
