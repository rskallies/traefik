// Package ech provides utilities for generating and working with
// Encrypted Client Hello (ECH) keys.
package ech

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/traefik/traefik/v3/pkg/tls"
)

// Generate creates a new ECH key for the given public name (SNI) and writes
// the PEM-encoded result to the provided writer.
func Generate(w io.Writer, publicName string) error {
	key, err := tls.NewECHKey(publicName)
	if err != nil {
		return fmt.Errorf("failed to generate ECH key for %s: %w", publicName, err)
	}

	data, err := tls.MarshalECHKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal ECH key for %s: %w", publicName, err)
	}

	if _, err = w.Write(data); err != nil {
		return fmt.Errorf("failed to write ECH key for %s: %w", publicName, err)
	}

	return nil
}

// GenerateMultiple creates ECH keys for multiple public names and writes
// all PEM-encoded results to the provided writer.
func GenerateMultiple(w io.Writer, publicNames []string) error {
	for _, name := range publicNames {
		if err := Generate(w, name); err != nil {
			return err
		}
	}
	return nil
}

// ExportConfigList reads an ECH PEM file and writes the base64-encoded
// ECHConfigList to w, suitable for use in DNS HTTPS records (ech= parameter).
func ExportConfigList(w io.Writer, pemFile string) error {
	data, err := os.ReadFile(pemFile)
	if err != nil {
		return fmt.Errorf("failed to read PEM file: %w", err)
	}

	key, err := tls.UnmarshalECHKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse ECH key: %w", err)
	}

	configList, err := tls.ECHConfigToConfigList(key.Config)
	if err != nil {
		return fmt.Errorf("failed to build ECH config list: %w", err)
	}

	_, err = fmt.Fprintln(w, base64.StdEncoding.EncodeToString(configList))
	return err
}
