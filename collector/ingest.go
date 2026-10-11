package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
)

const insertQuery = "INSERT INTO netflow.flows " +
	"(bytes, packets, src_addr, dst_addr, proto, src_port, dst_port, " +
	"src_as, dst_as, src_as_org, dst_as_org, src_country, dst_country) FORMAT JSONEachRow"

type flowInput struct {
	Bytes      uint64 `json:"bytes"`
	Packets    uint64 `json:"packets"`
	SrcAddr    string `json:"src_addr"`
	DstAddr    string `json:"dst_addr"`
	Proto      uint8  `json:"proto"`
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	SrcAS      uint32 `json:"src_as"`
	DstAS      uint32 `json:"dst_as"`
	SrcCountry string `json:"src_country"`
	DstCountry string `json:"dst_country"`
}

type flowRow struct {
	Bytes      uint64 `json:"bytes"`
	Packets    uint64 `json:"packets"`
	SrcAddr    string `json:"src_addr"`
	DstAddr    string `json:"dst_addr"`
	Proto      uint8  `json:"proto"`
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	SrcAS      uint32 `json:"src_as"`
	DstAS      uint32 `json:"dst_as"`
	SrcASOrg   string `json:"src_as_org"`
	DstASOrg   string `json:"dst_as_org"`
	SrcCountry string `json:"src_country"`
	DstCountry string `json:"dst_country"`
}

type asnResolver interface {
	ASN(net.IP) (*geoip2.ASN, error)
}

func loadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open env file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || !validEnvKey(key) {
			return fmt.Errorf("invalid env assignment on line %d", lineNumber)
		}
		value, err = parseEnvValue(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("invalid env value on line %d: %w", lineNumber, err)
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set env variable on line %d: %w", lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read env file: %w", err)
	}
	return nil
}

func validEnvKey(key string) bool {
	for i := 0; i < len(key); i++ {
		char := key[i]
		if char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' ||
			(i > 0 && char >= '0' && char <= '9') {
			continue
		}
		return false
	}
	return key != ""
}

func parseEnvValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if value[0] == '\'' || value[0] == '"' {
		quote := value[0]
		end := strings.IndexByte(value[1:], quote)
		if end < 0 {
			return "", errors.New("unterminated quoted value")
		}
		end++
		if trailing := strings.TrimSpace(value[end+1:]); trailing != "" && !strings.HasPrefix(trailing, "#") {
			return "", errors.New("unexpected text after quoted value")
		}
		return value[1:end], nil
	}
	if comment := strings.Index(value, " #"); comment >= 0 {
		value = strings.TrimSpace(value[:comment])
	}
	return value, nil
}

func decodeAddress(encoded string) (string, error) {
	packed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode base64 address: %w", err)
	}
	if len(packed) != net.IPv4len && len(packed) != net.IPv6len {
		return "", fmt.Errorf("decoded address has invalid length %d", len(packed))
	}
	ip := net.IP(packed)
	if ip.To16() == nil {
		return "", errors.New("decoded address is not a valid IP address")
	}
	return ip.String(), nil
}

func normalize(input flowInput) (flowRow, error) {
	srcAddr, err := decodeAddress(input.SrcAddr)
	if err != nil {
		return flowRow{}, fmt.Errorf("src_addr: %w", err)
	}
	dstAddr, err := decodeAddress(input.DstAddr)
	if err != nil {
		return flowRow{}, fmt.Errorf("dst_addr: %w", err)
	}

	return flowRow{
		Bytes:      input.Bytes,
		Packets:    input.Packets,
		SrcAddr:    srcAddr,
		DstAddr:    dstAddr,
		Proto:      input.Proto,
		SrcPort:    input.SrcPort,
		DstPort:    input.DstPort,
		SrcAS:      input.SrcAS,
		DstAS:      input.DstAS,
		SrcCountry: input.SrcCountry,
		DstCountry: input.DstCountry,
	}, nil
}

func resolveOrganizations(row *flowRow, resolver asnResolver) error {
	if resolver == nil {
		return errors.New("ASN database is not configured")
	}
	srcASN, err := resolver.ASN(net.ParseIP(row.SrcAddr))
	if err != nil {
		return fmt.Errorf("resolve src_as_org for %s: %w", row.SrcAddr, err)
	}
	dstASN, err := resolver.ASN(net.ParseIP(row.DstAddr))
	if err != nil {
		return fmt.Errorf("resolve dst_as_org for %s: %w", row.DstAddr, err)
	}
	row.SrcASOrg = srcASN.AutonomousSystemOrganization
	row.DstASOrg = dstASN.AutonomousSystemOrganization
	return nil
}

func insertBatch(client *http.Client, endpoint, username, password string, rows []flowRow) error {
	if len(rows) == 0 {
		return nil
	}

	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			return fmt.Errorf("encode insert row: %w", err)
		}
	}

	requestURL := strings.TrimRight(endpoint, "/") + "/?" + url.Values{
		"query": []string{insertQuery},
	}.Encode()
	request, err := http.NewRequest(http.MethodPost, requestURL, &payload)
	if err != nil {
		return fmt.Errorf("create ClickHouse request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-ndjson")
	request.SetBasicAuth(username, password)

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send ClickHouse insert: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		message, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
		if readErr != nil {
			return fmt.Errorf("ClickHouse returned %s; read response: %w", response.Status, readErr)
		}
		return fmt.Errorf("ClickHouse returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return fmt.Errorf("read ClickHouse response: %w", err)
	}
	return nil
}

func run(input io.Reader, client *http.Client, endpoint, username, password string, batchSize int, resolver asnResolver) error {
	if batchSize < 1 {
		return errors.New("CLICKHOUSE_BATCH_SIZE must be greater than zero")
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	batch := make([]flowRow, 0, batchSize)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record flowInput
		if err := json.Unmarshal(line, &record); err != nil {
			return fmt.Errorf("invalid flow JSON on input line %d: %w", lineNumber, err)
		}
		row, err := normalize(record)
		if err != nil {
			return fmt.Errorf("invalid flow on input line %d: %w", lineNumber, err)
		}
		if err := resolveOrganizations(&row, resolver); err != nil {
			return fmt.Errorf("invalid flow on input line %d: %w", lineNumber, err)
		}
		batch = append(batch, row)
		if len(batch) >= batchSize {
			if err := insertBatch(client, endpoint, username, password, batch); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read flow input: %w", err)
	}
	return insertBatch(client, endpoint, username, password, batch)
}

func openASNDatabase() (*geoip2.Reader, error) {
	path := "./db/asn.mmdb"

	reader, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ASN database %q: %w", path, err)
	}
	return reader, nil
}

func configuration() (string, string, string, int, error) {
	endpoint := os.Getenv("CLICKHOUSE_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8123"
	}
	if _, err := url.ParseRequestURI(endpoint); err != nil {
		return "", "", "", 0, fmt.Errorf("invalid CLICKHOUSE_URL: %w", err)
	}

	batchSize := 500
	if value := os.Getenv("CLICKHOUSE_BATCH_SIZE"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			return "", "", "", 0, errors.New("CLICKHOUSE_BATCH_SIZE must be a positive integer")
		}
		batchSize = parsed
	}

	username := os.Getenv("CLICKHOUSE_USER")
	if username == "" {
		username = "netflow"
	}
	return endpoint, username, os.Getenv("CLICKHOUSE_PASSWORD"), batchSize, nil
}

func main() {
	envFile := flag.String("env", "", "Load environment variables from a file")
	flag.Parse()

	var err error
	if *envFile != "" {
		err = loadEnvFile(*envFile)
	}
	var endpoint, username, password string
	var batchSize int
	if err == nil {
		endpoint, username, password, batchSize, err = configuration()
	}
	if err == nil {
		var resolver *geoip2.Reader
		resolver, err = openASNDatabase()
		if err == nil {
			defer resolver.Close()
			client := &http.Client{Timeout: 10 * time.Second}
			err = run(os.Stdin, client, endpoint, username, password, batchSize, resolver)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "netflow ClickHouse pipeline: %v\n", err)
		os.Exit(1)
	}
}
