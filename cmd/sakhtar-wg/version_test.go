package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteVersionJSON(t *testing.T) {
	var output bytes.Buffer
	if err := writeVersion(&output, true); err != nil {
		t.Fatal(err)
	}
	var metadata versionMetadata
	if err := json.Unmarshal(output.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Name != "sakhtar-wg" || metadata.Version == "" || metadata.Toolchain == "" {
		t.Fatalf("metadata = %+v", metadata)
	}
}
