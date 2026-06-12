package sign

import (
	"bytes"
	"testing"
)

func TestSignPDFFieldName(t *testing.T) {
	signData := cadesSignData(t)
	signData.Signature.FieldName = "user-test-1"
	signed := signTestFile(t, signData)

	if !bytes.Contains(signed, []byte("/T (user-test-1)")) {
		t.Error("missing /T (user-test-1); FieldName not honored")
	}
	if bytes.Contains(signed, []byte("/T (Signature 1)")) {
		t.Error("default /T (Signature 1) present alongside a custom FieldName")
	}
}

func TestSignPDFFieldNameDefault(t *testing.T) {
	signed := signTestFile(t, cadesSignData(t))

	if !bytes.Contains(signed, []byte("/T (Signature 1)")) {
		t.Error("missing default /T (Signature 1) with empty FieldName")
	}
}
