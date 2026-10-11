package main

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oschwald/geoip2-golang"
)

type testASNResolver map[string]string

func (r testASNResolver) ASN(ip net.IP) (*geoip2.ASN, error) {
	return &geoip2.ASN{AutonomousSystemOrganization: r[ip.String()]}, nil
}

func TestRunInsertsNormalizedFlow(t *testing.T) {
	source := `{"bytes":663,"packets":2,"src_addr":"` +
		base64.StdEncoding.EncodeToString([]byte{103, 193, 147, 149}) +
		`","dst_addr":"` +
		base64.StdEncoding.EncodeToString([]byte{118, 115, 126, 71}) +
		`","proto":17,"src_port":5514,"dst_port":762,"src_as":150986,"dst_as":17451,"src_country":"ID","dst_country":"ID","type":4}` + "\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "netflow" || password != "secret" {
			t.Errorf("unexpected Basic Auth credentials")
		}
		if !strings.Contains(r.URL.Query().Get("query"), "FORMAT JSONEachRow") {
			t.Errorf("unexpected insert query: %s", r.URL.Query().Get("query"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		expected := `{"bytes":663,"packets":2,"src_addr":"103.193.147.149","dst_addr":"118.115.126.71","proto":17,"src_port":5514,"dst_port":762,"src_as":150986,"dst_as":17451,"src_as_org":"Source Network","dst_as_org":"Destination Network","src_country":"ID","dst_country":"ID"}` + "\n"
		if string(body) != expected {
			t.Errorf("request body = %s, want %s", body, expected)
		}
	}))
	defer server.Close()

	resolver := testASNResolver{
		"103.193.147.149": "Source Network",
		"118.115.126.71":  "Destination Network",
	}
	if err := run(strings.NewReader(source), server.Client(), server.URL, "netflow", "secret", 10, resolver); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestNormalizeAllowsOmittedZeroValueFields(t *testing.T) {
	input := flowInput{
		SrcAddr: base64.StdEncoding.EncodeToString([]byte{103, 193, 147, 149}),
		DstAddr: base64.StdEncoding.EncodeToString([]byte{118, 115, 126, 71}),
	}

	row, err := normalize(input)
	if err != nil {
		t.Fatalf("normalize zero-value fields: %v", err)
	}
	if row.Bytes != 0 || row.Packets != 0 || row.Proto != 0 ||
		row.SrcPort != 0 || row.DstPort != 0 || row.SrcAS != 0 ||
		row.DstAS != 0 || row.SrcCountry != "" || row.DstCountry != "" {
		t.Fatalf("omitted fields should use zero values, got %+v", row)
	}
}

func TestResolveOrganizationsLeavesUnmappedAddressesEmpty(t *testing.T) {
	row := flowRow{SrcAddr: "103.193.147.149", DstAddr: "118.115.126.71"}
	if err := resolveOrganizations(&row, testASNResolver{}); err != nil {
		t.Fatalf("resolve empty ASN result: %v", err)
	}
	if row.SrcASOrg != "" || row.DstASOrg != "" {
		t.Fatalf("unmapped IP organizations should be empty, got src=%q dst=%q", row.SrcASOrg, row.DstASOrg)
	}
}

func TestLoadEnvFile(t *testing.T) {
	const fileVariable = "GO_FLOW_INGEST_TEST_FILE"
	const shellVariable = "GO_FLOW_INGEST_TEST_SHELL"
	t.Setenv(shellVariable, "shell-value")

	path := filepath.Join(t.TempDir(), "test.env")
	content := strings.Join([]string{
		"# comment",
		"export " + fileVariable + "='file value'",
		shellVariable + "=file-value",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := loadEnvFile(path); err != nil {
		t.Fatalf("load env file: %v", err)
	}
	if got := os.Getenv(fileVariable); got != "file value" {
		t.Errorf("%s = %q, want %q", fileVariable, got, "file value")
	}
	if got := os.Getenv(shellVariable); got != "shell-value" {
		t.Errorf("%s = %q, want shell value to take precedence", shellVariable, got)
	}
}
