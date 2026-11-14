package source

import (
	"archive/zip"
	"bytes"
	"context"
	"github.com/Lercas/prowl/tool/internal/model"
	"testing"
)

func TestPayloadBudgetAndMobileCRCEmitErrors(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "owned.env", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("owned payload contents")); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	damaged := append([]byte(nil), archive.Bytes()...)
	at := bytes.Index(damaged, []byte("owned payload contents"))
	if at < 0 {
		t.Fatal("fixture body missing")
	}
	damaged[at] ^= 1
	for _, mode := range []string{"payload-size", "mobile-size", "mobile-crc"} {
		t.Run(mode, func(t *testing.T) {
			coverage := model.NewCoverage()
			ctx := model.WithCoverage(context.Background(), coverage)
			var items <-chan model.Item
			if mode == "payload-size" {
				items = Payload(ctx, "owned.txt", []byte("owned payload contents"), 4)
			} else {
				data, max := archive.Bytes(), int64(4)
				if mode == "mobile-crc" {
					data, max = damaged, 100
				}
				var err error
				items, err = MobileBytes(ctx, "owned.apk", data, MobileOptions{MaxBytes: max, Strings: true})
				if err != nil {
					t.Fatal(err)
				}
			}
			failed := false
			for item := range items {
				failed = failed || item.Error != nil
			}
			// Source streams carry failure as Error Items; Pipeline turns them into incomplete reports.
			if !failed {
				t.Fatal("payload failure did not emit an Error Item")
			}

		})
	}
	if _, err := MobileBytes(context.Background(), "owned.apk", []byte("not a zip"), MobileOptions{}); err == nil {
		t.Fatal("broken mobile envelope accepted")
	}
}
