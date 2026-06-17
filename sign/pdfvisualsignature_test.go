package sign

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
)

func TestVisualSignature(t *testing.T) {
	input_file, err := os.Open("../testfiles/testfile20.pdf")
	if err != nil {
		t.Errorf("Failed to load test PDF")
		return
	}

	finfo, err := input_file.Stat()
	if err != nil {
		t.Errorf("Failed to load test PDF")
		return
	}
	size := finfo.Size()

	rdr, err := pdf.NewReader(input_file, size)
	if err != nil {
		t.Errorf("Failed to load test PDF")
		return
	}

	timezone, _ := time.LoadLocation("Europe/Tallinn")
	now := time.Date(2017, 9, 23, 14, 39, 0, 0, timezone)

	sign_data := SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Test",
				ContactInfo: "None",
				Date:        now,
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
	}

	sign_data.objectId = uint32(rdr.XrefInformation.ItemCount) + 3

	context := SignContext{
		PDFReader: rdr,
		InputFile: input_file,
		SignData:  sign_data,
	}

	expected_visual_signature := "<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [0 0 0 0]\n  /P 4 0 R\n  /F 132\n  /FT /Sig\n  /T (Signature 1)\n  /V 13 0 R\n>>\n"

	visual_signature, err := context.createVisualSignature(false, 1, [4]float64{0, 0, 0, 0})
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	if string(visual_signature) != expected_visual_signature {
		t.Errorf("Visual signature mismatch, expected\n%q\nbut got\n%q", expected_visual_signature, visual_signature)
	}
}

// TestIncPageUpdateInlineAnnots verifies createIncPageUpdate re-serializes an
// inline annotation dictionary (as e.g. FPDF2 emits /Annots) inline, rather
// than collapsing it into a dangling/self reference. digitorus/pdf reports a
// direct value's owning object via GetPtr(), so an inline annot's GetPtr().GetID()
// is the page's id; the old code wrote that as "<pageID> 0 R", dropping the
// annotation and corrupting the page.
func TestIncPageUpdateInlineAnnots(t *testing.T) {
	var b bytes.Buffer
	offsets := map[int]int{}
	b.WriteString("%PDF-1.4\n")
	offsets[1] = b.Len()
	b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	offsets[2] = b.Len()
	b.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
	offsets[3] = b.Len()
	b.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << >> " +
		"/Annots [<< /Type /Annot /Subtype /Text /Rect [10 10 30 30] /Contents (hello-inline) >>] >>\nendobj\n")
	xrefOff := b.Len()
	b.WriteString("xref\n0 4\n0000000000 65535 f \n")
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(&b, "%010d 00000 n \n", offsets[i])
	}
	b.WriteString("trailer\n<< /Size 4 /Root 1 0 R >>\n")
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xrefOff)
	data := b.Bytes()

	rdr, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("failed to read constructed PDF: %v", err)
	}

	context := SignContext{PDFReader: rdr}
	out, err := context.createIncPageUpdate(1, 5) // re-emit page 1, add widget object 5
	if err != nil {
		t.Fatalf("createIncPageUpdate: %v", err)
	}
	got := string(out)

	if !strings.Contains(got, "hello-inline") {
		t.Errorf("inline annotation was not preserved inline; got:\n%s", got)
	}
	if !strings.Contains(got, "5 0 R") {
		t.Errorf("new widget reference (5 0 R) was not appended; got:\n%s", got)
	}
	// The inline dict must not be collapsed into a bare reference to the page.
	if strings.Contains(got, "    3 0 R") {
		t.Errorf("inline annotation collapsed into a self-reference; got:\n%s", got)
	}
}
