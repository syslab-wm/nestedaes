package mu

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var Debug = false

func Dlogf(format string, a ...any) {
	if !Debug {
		return
	}
	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}
	log.Printf(format, a...)
}

func Die(format string, a ...any) {
	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}

func Panicf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	panic(msg)
}

func UNUSED(v ...any) {}

func BoolToInt(v bool) int {
	if v {
		return 1
	} else {
		return 0
	}
}

func WriteAll(w io.Writer, data []byte) {
	n, err := w.Write(data)
	if err != nil {
		// write returns a non-nil error when n != len(b)
		Die("error: partial write %d/%d: %v", n, len(data), err)
	}
}
