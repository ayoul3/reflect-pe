package lib_test

import (
	"debug/pe"
	. "unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/ayoul3/reflect-pe/lib"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ReplaceWord", func() {
	Context("When the keyword is there", func() {
		It("should replace both utf8 and utf16", func() {
			bin := &MockBin{}
			bin.UpdateData([]byte("abcdefghnullstringdontcare\x61\x00\x62\x00\x63\x00\x64\x00\x65\x00\x66\x00\x67\x00\x68\x00"))
			lib.ReplaceWord(bin, "abcdefgh")
			Expect(bin.Data[0:8]).ToNot(Equal([]byte("abcdefgh")))
			Expect(bin.Data[len(bin.Data)-8:]).ToNot(Equal([]byte("\x65\x00\x66\x00\x67\x00\x68\x00")))
		})
	})
})

func NewAllocatedMock(size uint) *MockBin {
	api := lib.NewWinAPI()
	addr, err := api.VirtualAlloc(size)
	if err != nil {
		log.Panicf("Cannot allocate memory for mock")
	}
	return &MockBin{Address: Pointer(addr)}
}

var _ = Describe("CopySections", func() {
	Describe("CopySections", func() {
		Context("When the copy works", func() {
			It("destination should have sections", func() {
				src, dst := &MockBin{}, &MockBin{}
				addr := []pe.SectionHeader32{
					{Name: [8]uint8{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41}},
					{Name: [8]uint8{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}},
				}
				src.Address = Pointer(&addr[0])
				lib.CopySections(&MockWin{}, src, dst)
				Expect(len(dst.GetSections())).To(Equal(2))
				Expect(dst.GetSections()[0].Name).To(Equal("AAAAAAAA"))
			})
		})
	})
	Describe("LoadLibraries", func() {
		Context("When loading two libraries", func() {
			It("destination should have sections", func() {
				bin := &MockBin{}
				addr := []lib.ImageImportDescriptor{
					{Name: 0x41},
					{Name: 0x42},
					{Name: 0},
				}
				bin.Address = Pointer(&addr[0])
				lib.LoadLibraries(&MockWin{}, bin)
				Expect(len(bin.GetModules())).To(Equal(2))
			})
		})
		Context("When one library fails", func() {
			It("should return an error", func() {
				bin := &MockBin{}
				win := &MockWin{ShouldFailLibrary: true}
				addr := []lib.ImageImportDescriptor{
					{Name: 0x41},
					{},
				}
				bin.Address = Pointer(&addr[0])
				err := lib.LoadLibraries(win, bin)
				Expect(err).To(HaveOccurred())
			})
		})
	})
	Describe("LoadFunction", func() {
		Context("When loading two functions", func() {
			It("destination should have sections", func() {
				bin := &MockBin{}
				addr := []lib.ImageThunkData{
					{AddressOfData: 0x1},
					{AddressOfData: 0xF000000000000042},
					{},
				}
				module := lib.Module{}
				bin.Address = Pointer(&addr[0])
				lib.LoadFunction(&MockWin{}, bin, module)
				Expect(len(bin.GetFunctions())).To(Equal(2))
				Expect(bin.GetFunctions()[0].Name).To(Equal("name"))
				Expect(bin.GetFunctions()[1].Name).To(Equal("#66"))
			})
		})
		Context("When loading two functions", func() {
			It("destination should have sections", func() {
				bin := &MockBin{}
				win := &MockWin{ShouldFailFunction: true}
				addr := []lib.ImageThunkData{
					{AddressOfData: 0x1},
					{},
				}
				module := lib.Module{}
				bin.Address = Pointer(&addr[0])
				err := lib.LoadFunction(win, bin, module)
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
