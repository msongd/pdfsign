package sign

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/mattetti/filebuffer"
)

type CatalogData struct {
	ObjectId   uint32
	RootString string
}

type TSA struct {
	URL      string
	Username string
	Password string
}

type RevocationFunction func(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error

type SignData struct {
	Signature          SignDataSignature
	Signer             crypto.Signer
	DigestAlgorithm    crypto.Hash
	Certificate        *x509.Certificate
	CertificateChains  [][]*x509.Certificate
	TSA                TSA
	RevocationData     revocation.InfoArchival
	RevocationFunction RevocationFunction
	Appearance         Appearance

	// TimestampFunction returns a DER-encoded RFC 3161 TimeStampToken (the
	// token itself, not a full TSA response) over digest, where digest is
	// the DigestAlgorithm hash of the content to be timestamped. When set it
	// takes precedence over TSA.URL, for both the CMS signature timestamp
	// and CertType TimeStampSignature document timestamps. It is called with
	// context.Background(); implementations needing cancellation or
	// deadlines should capture their own context in a closure.
	TimestampFunction func(context.Context, []byte) ([]byte, error)

	objectId uint32
}

// Appearance represents the appearance of the signature
type Appearance struct {
	Visible bool

	Page        uint32
	LowerLeftX  float64
	LowerLeftY  float64
	UpperRightX float64
	UpperRightY float64

	Image            []byte // Image data to use as signature appearance
	ImageAsWatermark bool   // If true, the text will be drawn over the image
}

type VisualSignData struct {
	pageObjectId uint32
	objectId     uint32
}

type InfoData struct {
	ObjectId uint32
}

//go:generate stringer -type=CertType
type CertType uint

const (
	CertificationSignature CertType = iota + 1
	ApprovalSignature
	UsageRightsSignature
	TimeStampSignature
)

//go:generate stringer -type=DocMDPPerm
type DocMDPPerm uint

const (
	DoNotAllowAnyChangesPerms DocMDPPerm = iota + 1
	AllowFillingExistingFormFieldsAndSignaturesPerms
	AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms
)

type SignDataSignature struct {
	CertType   CertType
	DocMDPPerm DocMDPPerm
	Info       SignDataSignatureInfo

	// CAdES selects PAdES mode (ETSI EN 319 142-1): the signature dictionary
	// uses /SubFilter /ETSI.CAdES.detached, the CMS carries no signingTime
	// signed attribute and no Adobe adbe-revocationInfoArchival attribute,
	// and the claimed signing time is always written to the dictionary /M
	// entry.
	CAdES bool

	// FieldName is the /T (field title) of the signature form field created
	// for this signature. Empty selects the default "Signature N" (N = number
	// of existing signatures + 1). Callers must ensure uniqueness within the
	// document; duplicate field names produce undefined viewer behavior.
	FieldName string
}

type SignDataSignatureInfo struct {
	Name        string
	Location    string
	Reason      string
	ContactInfo string
	Date        time.Time
}

type SignContext struct {
	InputFile              io.ReadSeeker
	OutputFile             io.Writer
	OutputBuffer           *filebuffer.Buffer
	SignData               SignData
	CatalogData            CatalogData
	VisualSignData         VisualSignData
	InfoData               InfoData
	PDFReader              *pdf.Reader
	NewXrefStart           int64
	ByteRangeValues        []int64
	SignatureMaxLength     uint32
	SignatureMaxLengthBase uint32

	existingSignatures []SignData
	lastXrefID         uint32
	newXrefEntries     []xrefEntry
	updatedXrefEntries []xrefEntry
}
