// +build windows

package clr

import (
	"bytes"
	"fmt"
	"log"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

const S_OK = 0x0

func checkOK(hr uintptr, caller string) error {
	if hr != S_OK {
		return fmt.Errorf("%s returned 0x%08x", caller, hr)
	} else {
		return nil
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func utf16Le(s string) []byte {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	var buf bytes.Buffer
	t := transform.NewWriter(&buf, enc)
	t.Write([]byte(s))
	return buf.Bytes()
}
