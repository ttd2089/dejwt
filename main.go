package main

import(
	"bufio"
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

var errInvalidJWT error = errors.New("input was not a valid JWT")

func main() {
	output, err := decode(bufio.NewReader(os.Stdin))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing JWT: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", output)
}

func decode(r *bufio.Reader) ([]byte, error) {

	header, err := decodeJSONPart(r, "header")
	if err != nil {
		return nil, fmt.Errorf("error decoding JWT header: %w", err)
	}

	payload, err := decodeJSONPart(r, "payload")
	if err != nil {
		return nil, fmt.Errorf("error decoding JWT payload: %w", err)
	}

	header = append(header, '\n')
	header = append(header, payload...)
	return header, err
}

func decodeJSONPart(r *bufio.Reader, part string) ([]byte, error) {

	partData, err := r.ReadBytes('.')
	if err != nil {
		return nil, fmt.Errorf("failed to read %s bytes: %v", part, err)
	}
	fmt.Printf("(%s) partData: %s\n", part, partData)

	if partData[len(partData)-1] != '.' {
		return nil, fmt.Errorf("incorrectly terminated %s", part)
	}
	partData = partData[:len(partData)-1]
	fmt.Printf("(%s) partData[:-1]: %s\n", part, partData)

	if part == "payload" {
		fmt.Printf("[0:72] = %s\n", partData[:72])
		fmt.Printf("[72:] = %s\n", partData[72:])
	}

	decodedPart, err := b64.RawURLEncoding.DecodeString(string(partData))
	if err != nil {
		return nil, fmt.Errorf("%s contained invalid base64 data: %v", part, err)
	}
	fmt.Printf("(%s) decodedPart: %s\n", part, partData)

	var indented bytes.Buffer
	if err = json.Indent(&indented, decodedPart, "", "  "); err != nil {
		return nil, fmt.Errorf("%s contained invalid JSON", part)
	}
	return indented.Bytes(), nil
}
