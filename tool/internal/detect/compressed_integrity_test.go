package detect

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestCompressedIntegrityDoesNotUseEntropyOrPrefixLength(t *testing.T) {
	d := newDetector(t)
	for _, gzipFormat := range []bool{false, true} {
		for _, payload := range []string{"short", strings.Repeat(" ", 4096) + "AWS=" + depthAWSKey + "\n"} {
			good := compressedFixture(t, payload, gzipFormat)
			damaged := bytes.Clone(good)
			damaged[len(damaged)-1] ^= 0x80
			decoded, ok, limited := inflateStatus(damaged)
			if !ok || !limited || string(decoded) != payload {
				t.Errorf("damaged real stream discarded: gzip=%v length=%d", gzipFormat, len(payload))
			}
			if strings.Contains(payload, depthAWSKey) {
				matches, limited := d.ScanCtxWithStatus(t.Context(), "blob: "+base64.StdEncoding.EncodeToString(damaged))
				if !limited || findType(matches, "aws_access_key_id") == nil {
					t.Error("low-entropy damaged text hid a detected credential")
				}
			}
		}
	}
}

func TestCompressedOutputLimitSurvivesNonPrintablePrefix(t *testing.T) {
	for _, gzipFormat := range []bool{false, true} {
		payload := strings.Repeat("\x00", maxInflateBytes+1)
		blob := base64.StdEncoding.EncodeToString(compressedFixture(t, payload, gzipFormat))
		_, ok, limited := decodeBlobStatus(blob)
		if ok || !limited {
			t.Fatal("uninspected compressed tail became a complete binary rejection")
		}
	}
}

func TestEmptyStreamChecksumFailureCannotHideUnreadGzipMember(t *testing.T) {
	d := newDetector(t)
	for _, gzipFormat := range []bool{false, true} {
		valid := compressedFixture(t, "", gzipFormat)
		if _, _, limited := inflateStatus(valid); limited {
			t.Fatal("valid empty stream marked incomplete")
		}
		damaged := bytes.Clone(valid)
		damaged[len(damaged)-1] ^= 0x80
		if gzipFormat {
			damaged = append(damaged, compressedFixture(t, "AWS="+depthAWSKey+"\n", true)...)
		} else {
			// Keep the empty zlib case above the outer base64-candidate minimum.
			damaged = append(damaged, make([]byte, 16)...)
		}
		if _, _, limited := inflateStatus(damaged); !limited {
			t.Errorf("empty deflate checksum failure lost uncertainty: gzip=%v", gzipFormat)
		}
		if _, limited := d.ScanCtxWithStatus(t.Context(), "blob: "+base64.StdEncoding.EncodeToString(damaged)); !limited {
			t.Errorf("unread tail became a complete scan: gzip=%v", gzipFormat)
		}
	}
}
