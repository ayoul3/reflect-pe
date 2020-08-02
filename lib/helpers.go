package lib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"
	"unicode/utf16"
	. "unsafe"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// safely duplicate a pointer before converting it to uintptr to keep GC from cleaning it
func ptrValue(ptr Pointer) uintptr {
	return uintptr(Pointer(ptr))
}

func uintAddr(addr interface{}) uintptr {
	return uintptr(Pointer(&addr))
}

func uint16Val(ptr Pointer, offset uint) uint16 {
	return *(*uint16)(Pointer(ptrValue(ptr) + uintptr(offset)))
}
func uint32Val(ptr Pointer, offset uint) uint32 {
	return *(*uint32)(Pointer(ptrValue(ptr) + uintptr(offset)))
}

func ptrOffset(ptr Pointer, offset uintptr) Pointer {
	return Pointer(ptrValue(ptr) + offset)
}

func addrOffset(addr uintptr, offset uintptr) Pointer {
	return Pointer(addr + offset)
}

func isMSBSet(num uint) bool {
	uintSize := 32 << (^uint(0) >> 32 & 1)
	return num>>(uintSize-1) == 1
}

func randInt(min, max int) int {
	return rand.Intn(max-min) + min
}

func reverse(s string) string {
	rns := []rune(s)
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		rns[i], rns[j] = rns[j], rns[i]
	}

	return string(rns)
}

func intToByteArray(num uintptr) []byte {
	size := int(Sizeof(num))
	arr := make([]byte, size)
	for i := 0; i < size; i++ {
		byt := *(*uint8)(Pointer(uintptr(Pointer(&num)) + uintptr(i)))
		arr[i] = byt
	}
	return arr
}

func formatAddr(addr uintptr) []byte {
	size := Sizeof(uintptr(0))
	b := make([]byte, size)
	switch size {
	case 4:
		binary.LittleEndian.PutUint32(b, uint32(addr))
	default:
		binary.LittleEndian.PutUint64(b, uint64(addr))
	}
	return b
}

func formatAddrVar(addr uintptr, size int) []byte {
	b := make([]byte, size)
	switch size {
	case 4:
		binary.LittleEndian.PutUint32(b, uint32(addr))
	default:
		binary.LittleEndian.PutUint64(b, uint64(addr))
	}
	return b
}

func formatPtr(ptr Pointer) []byte {
	return formatAddr(ptrValue(ptr))
}

func createStrPtr(str string) Pointer {
	strBytes := make([]byte, 0)
	strBytes = append(strBytes, []byte(str)...)
	strBytes = append(strBytes, 0x00)
	return Pointer(&strBytes[0])
}

func buildArgvPointers(argvs []string) Pointer {
	ptrAddrAllArgs := make([]byte, 0)
	addrAllArgs := make([]byte, 0)

	for _, s := range argvs {
		strPtr := createStrPtr(s)
		addrAllArgs = append(addrAllArgs, formatPtr(strPtr)...)
	}
	addrAllArgs = append(addrAllArgs, formatAddr(0x0000000000000000)...)
	ptrAddrAllArgs = append(ptrAddrAllArgs, formatPtr(Pointer(&addrAllArgs[0]))...)
	return Pointer(&ptrAddrAllArgs[0])
}

func buildArgvPointerUnicode(argvs []string) Pointer {
	addrAllArgs := make([]byte, 0)

	for _, s := range argvs {
		runes := utf16.Encode([]rune(s))
		runes = append(runes, 0x00)
		addrAllArgs = append(addrAllArgs, formatPtr(Pointer(&runes[0]))...)
	}
	addrAllArgs = append(addrAllArgs, formatAddr(0x0000000000000000)...)
	return Pointer(&addrAllArgs[0])
}

func utf16Le(s string) []byte {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	var buf bytes.Buffer
	t := transform.NewWriter(&buf, enc)
	t.Write([]byte(s))
	return buf.Bytes()
}

func utf16LeStr(s string) string {
	return string(utf16Le(s))
}

func shuffle(in string) string {
	rand.Seed(time.Now().Unix())
	inRune := []rune(in)
	rand.Shuffle(len(inRune), func(i, j int) {
		inRune[i], inRune[j] = inRune[j], inRune[i]
	})
	return string(inRune)
}

func parseOrdinal(ordinal uint) (Pointer, string) {
	funcOrdinal := uint16(ordinal)
	ptrName := Pointer(uintptr(funcOrdinal))
	funcName := fmt.Sprintf("#%d", funcOrdinal)
	return ptrName, funcName
}

func parseFuncAddress(api WinAPI, base, offset uintptr) (Pointer, string) {
	pImageImportByName := (*ImageImportByName)(Pointer(base + offset))
	ptrName := Pointer(&pImageImportByName.Name)
	funcName := string(api.CstrVal(ptrName))
	return ptrName, funcName
}

var Headers = map[string]string{
	"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.6,image/webp,*/*;q=0.5",
	"user-agent":                "Mozilla/5.0 (Windows NT 8.0; Win64; x64; rv:69.0) Gecko/20100115 Firefox/89.85",
	"accept-language":           "en-US,en;q=0.5",
	"accept-encoding":           "gzip, deflate",
	"dnt":                       "1",
	"connection":                "close",
	"upgrade-insecure-requests": "1",
}

func httpGet(path string) ([]byte, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", path, nil)
	for key, value := range Headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}
