package sign

import (
	"bytes"
	gocontext "context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

var (
	oidAttributeSigningTime        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttributeSigningCertificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidAttributeAdbeRevocation     = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}
	oidAttributeTimeStampToken     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
)

func signTestFile(t *testing.T, signData SignData) []byte {
	t.Helper()
	input, err := os.Open("../testfiles/testfile12.pdf")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	fi, err := input.Stat()
	if err != nil {
		t.Fatal(err)
	}
	rdr, err := pdf.NewReader(input, fi.Size())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Sign(input, &out, rdr, fi.Size(), signData); err != nil {
		t.Fatalf("sign: %s", err)
	}
	return out.Bytes()
}

// extractCMS pulls the last /Contents hex string out of a signed PDF and
// parses it as CMS.
func extractCMS(t *testing.T, signed []byte) *pkcs7.PKCS7 {
	t.Helper()
	marker := []byte("/Contents<")
	idx := bytes.LastIndex(signed, marker)
	if idx < 0 {
		t.Fatal("no /Contents found in signed output")
	}
	start := idx + len(marker)
	end := bytes.IndexByte(signed[start:], '>')
	if end < 0 {
		t.Fatal("unterminated /Contents hex string")
	}
	der, err := hex.DecodeString(string(signed[start : start+end]))
	if err != nil {
		t.Fatalf("decode /Contents hex: %s", err)
	}
	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatalf("parse CMS: %s", err)
	}
	return p7
}

func hasSignedAttribute(p7 *pkcs7.PKCS7, oid asn1.ObjectIdentifier) bool {
	for _, attr := range p7.Signers[0].AuthenticatedAttributes {
		if attr.Type.Equal(oid) {
			return true
		}
	}
	return false
}

func hasUnsignedAttribute(p7 *pkcs7.PKCS7, oid asn1.ObjectIdentifier) bool {
	for _, attr := range p7.Signers[0].UnauthenticatedAttributes {
		if attr.Type.Equal(oid) {
			return true
		}
	}
	return false
}

// newTestTimestampFunction returns a SignData.TimestampFunction backed by an
// in-test TSA (self-signed certificate with the timestamping EKU).
func newTestTimestampFunction(t *testing.T) func(gocontext.Context, []byte) ([]byte, error) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "pdfsign test TSA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return func(_ gocontext.Context, digest []byte) ([]byte, error) {
		ts := timestamp.Timestamp{
			HashAlgorithm:     crypto.SHA256,
			HashedMessage:     digest,
			Time:              time.Now(),
			Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
			AddTSACertificate: true,
		}
		resp, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
		if err != nil {
			return nil, err
		}
		parsed, err := timestamp.ParseResponse(resp)
		if err != nil {
			return nil, err
		}
		// A TimestampFunction returns the raw TimeStampToken, not the
		// full TSA response.
		return parsed.RawToken, nil
	}
}

func cadesSignData(t *testing.T) SignData {
	t.Helper()
	cert, pkey := loadCertificateAndKey(t)
	return SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name: "CAdES test",
				Date: time.Now().Local(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
			CAdES:      true,
		},
		Signer:          pkey,
		DigestAlgorithm: crypto.SHA256,
		Certificate:     cert,
	}
}

func TestSignPDFCAdES(t *testing.T) {
	signed := signTestFile(t, cadesSignData(t))

	if !bytes.Contains(signed, []byte("/SubFilter /ETSI.CAdES.detached")) {
		t.Error("missing /SubFilter /ETSI.CAdES.detached")
	}
	if !bytes.Contains(signed, []byte(" /M ")) {
		t.Error("missing /M (claimed signing time) in the signature dictionary")
	}

	p7 := extractCMS(t, signed)
	if hasSignedAttribute(p7, oidAttributeSigningTime) {
		t.Error("signingTime signed attribute present; PAdES forbids it")
	}
	if hasSignedAttribute(p7, oidAttributeAdbeRevocation) {
		t.Error("adbe-revocationInfoArchival attribute present; PAdES forbids it")
	}
	if !hasSignedAttribute(p7, oidAttributeSigningCertificate) {
		t.Error("signing-certificate-v2 signed attribute missing; PAdES requires it")
	}
	// The CMS is detached (content lives in the PDF ByteRange), so
	// cryptographic verification happens at file level below.
	tmp := filepath.Join(t.TempDir(), "cades.pdf")
	if err := os.WriteFile(tmp, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	verifySignedFile(t, f, "testfile12.pdf")
}

func TestSignPDFLegacyDefaultsUnchanged(t *testing.T) {
	signData := cadesSignData(t)
	signData.Signature.CAdES = false
	signed := signTestFile(t, signData)

	if !bytes.Contains(signed, []byte("/SubFilter /adbe.pkcs7.detached")) {
		t.Error("legacy mode lost /SubFilter /adbe.pkcs7.detached")
	}
	p7 := extractCMS(t, signed)
	if !hasSignedAttribute(p7, oidAttributeSigningTime) {
		t.Error("legacy mode lost the signingTime signed attribute")
	}
	if !hasSignedAttribute(p7, oidAttributeAdbeRevocation) {
		t.Error("legacy mode lost the adbe-revocationInfoArchival attribute")
	}
}

func TestSignPDFCAdESWithTimestampFunction(t *testing.T) {
	signData := cadesSignData(t)
	signData.TimestampFunction = newTestTimestampFunction(t)
	signed := signTestFile(t, signData)

	p7 := extractCMS(t, signed)
	if !hasUnsignedAttribute(p7, oidAttributeTimeStampToken) {
		t.Error("signature timestamp unsigned attribute missing")
	}
	if hasSignedAttribute(p7, oidAttributeSigningTime) {
		t.Error("signingTime signed attribute present; PAdES forbids it")
	}
	// CAdES keeps the claimed time in /M even when timestamped.
	if !bytes.Contains(signed, []byte(" /M ")) {
		t.Error("missing /M (claimed signing time) in the signature dictionary")
	}
}

func TestTimestampPDFFileWithTimestampFunction(t *testing.T) {
	signed := signTestFile(t, SignData{
		Signature: SignDataSignature{
			CertType: TimeStampSignature,
		},
		DigestAlgorithm:   crypto.SHA256,
		TimestampFunction: newTestTimestampFunction(t),
	})

	if !bytes.Contains(signed, []byte("/SubFilter /ETSI.RFC3161")) {
		t.Error("missing /SubFilter /ETSI.RFC3161")
	}
	// The embedded Contents must be a parseable TimeStampToken.
	extractCMS(t, signed)
}
