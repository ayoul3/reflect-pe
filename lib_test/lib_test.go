package lib_test

import (
	"github.com/ayoul3/reflect-pe/lib"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Loading", func() {

	Describe("NewBinaryFromDisk", func() {
		Context("When file is not PE", func() {
			It("should trigger error", func() {
				_, err := lib.NewBinaryFromDisk("./lib_test.go")
				Expect(err).To(HaveOccurred())
			})
		})
		Context("When file does not exist", func() {
			It("should trigger error", func() {
				_, err := lib.NewBinaryFromDisk("./random.exe")
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
