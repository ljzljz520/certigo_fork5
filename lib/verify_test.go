// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testValidSPIFFEID = "spiffe://example.org/path/service"

// testCA is a locally generated X.509 certification authority used to sign
// test certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// svidFixture holds two independent local roots: a trusted one referenced by
// the CA bundle and an untrusted one used to build chains that must not anchor.
type svidFixture struct {
	trusted *testCA
	other   *testCA
	caPath  string
}

func newSVIDFixture(t *testing.T) *svidFixture {
	t.Helper()
	trusted := newTestCA(t, "Trusted SPIFFE Root")
	other := newTestCA(t, "Other SPIFFE Root")

	caPath := filepath.Join(t.TempDir(), "ca-bundle.pem")
	require.NoError(t, os.WriteFile(caPath, trusted.pem, 0o600))

	return &svidFixture{trusted: trusted, other: other, caPath: caPath}
}

// newSVIDLeafTemplate builds a template for a conforming X.509-SVID leaf
// certificate carrying spiffeID. Modify the returned template to craft
// non-conforming certificates.
func newSVIDLeafTemplate(t *testing.T, spiffeID string) *x509.Certificate {
	t.Helper()

	var uris []*url.URL
	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		require.NoError(t, err)
		uris = []*url.URL{u}
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "svid-leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		URIs: uris,
	}
}

// signLeaf creates and parses a leaf certificate from template, signed by
// issuer (or self-signed when issuer is nil).
func signLeaf(t *testing.T, template *x509.Certificate, issuer *testCA) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	parent := template
	var parentKey any = key
	if issuer != nil {
		parent = issuer.cert
		parentKey = issuer.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// nonCriticalDigitalSignatureKeyUsage returns a keyUsage extension carrying
// only digitalSignature, marked non-critical. Go's x509 package always emits
// key usage as critical, so the extension has to be crafted manually.
func nonCriticalDigitalSignatureKeyUsage(t *testing.T) pkix.Extension {
	t.Helper()

	// Key usage is an ASN.1 BIT STRING with digitalSignature at bit 0 (MSB).
	value, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 8})
	require.NoError(t, err)

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
		Critical: false,
		Value:    value,
	}
}

func TestParseLeafSPIFFEID(t *testing.T) {
	valid := []string{
		"spiffe://example.org/path/service",
		"spiffe://example.com/payments/mysql",
		"spiffe://k8s-west.example.com/ns/staging/sa/default",
		"spiffe://example.org/9eebccd2-12bf-40a6-b262-65fe0487d453",
		"spiffe://trust_domain.example.com/a",
		"spiffe://a/p",
		"spiffe://1.2.3.4/workload",
		"spiffe://example.org/path.dotted-segment_name",
		"spiffe://example.org/UPPERCASE-PATH",
	}
	for _, id := range valid {
		t.Run("valid/"+id, func(t *testing.T) {
			_, err := parseLeafSPIFFEID(id)
			require.NoError(t, err, "expected %q to be accepted", id)
		})
	}

	invalid := []string{
		"",
		"http://example.org/path",
		"spiffe://",
		"spiffe:///path",
		"spiffe://example.org",       // leaf SVIDs require a non-root path
		"spiffe://example.org/",      // root path with trailing slash
		"spiffe://example.org/a/",    // trailing slash
		"spiffe://example.org/a//b",  // empty segment
		"spiffe://example.org/a/./b", // relative segment
		"spiffe://example.org/a/../b",
		"spiffe://Example.ORG/a", // trust domain must be lowercase
		"spiffe://example.org:8080/a",
		"spiffe://user@example.org/a",
		"spiffe://example.org/a?query",
		"spiffe://example.org/a#fragment",
		"spiffe://example.org/a%20b",
		"spiffe://exa%6dple.org/a",
		"spiffe://example.org/a+b",
	}
	for _, id := range invalid {
		t.Run("invalid/"+id, func(t *testing.T) {
			_, err := parseLeafSPIFFEID(id)
			assert.Error(t, err, "expected %q to be rejected", id)
		})
	}
}

// TestVerifyCertificateSVIDProfile exercises the strict leaf profile without
// involving path validation: certificates are generated locally and checked
// directly.
func TestVerifyCertificateSVIDProfile(t *testing.T) {
	const illegalButMatchingID = "spiffe://Dev.Example.com/path/service"

	secondURI, err := url.Parse("spiffe://example.org/path/other")
	require.NoError(t, err)

	tests := []struct {
		name           string
		spiffeID       string
		expectedID     string
		modifyTemplate func(*x509.Certificate)
		wantErr        string
	}{
		{
			name:       "conforming leaf SVID",
			spiffeID:   testValidSPIFFEID,
			expectedID: testValidSPIFFEID,
		},
		{
			name:       "illegal URI rejected even though strings match",
			spiffeID:   illegalButMatchingID,
			expectedID: illegalButMatchingID,
			wantErr:    "not a valid X.509-SVID identity",
		},
		{
			name:       "missing non-root path",
			spiffeID:   "spiffe://example.org",
			expectedID: "spiffe://example.org",
			wantErr:    "non-root path",
		},
		{
			name:       "identity mismatch",
			spiffeID:   testValidSPIFFEID,
			expectedID: "spiffe://example.org/path/other",
			wantErr:    "not spiffe://example.org/path/other",
		},
		{
			name:     "missing digitalSignature key usage",
			spiffeID: testValidSPIFFEID,
			modifyTemplate: func(c *x509.Certificate) {
				c.KeyUsage = x509.KeyUsageKeyEncipherment
			},
			wantErr: "digitalSignature",
		},
		{
			name:     "forbidden keyCertSign and cRLSign",
			spiffeID: testValidSPIFFEID,
			modifyTemplate: func(c *x509.Certificate) {
				c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
			},
			wantErr: "keyCertSign or cRLSign",
		},
		{
			name:     "non-critical key usage extension",
			spiffeID: testValidSPIFFEID,
			modifyTemplate: func(c *x509.Certificate) {
				c.KeyUsage = 0
				c.ExtraExtensions = []pkix.Extension{nonCriticalDigitalSignatureKeyUsage(t)}
			},
			wantErr: "marked critical",
		},
		{
			name:     "disallowed extended key usage",
			spiffeID: testValidSPIFFEID,
			modifyTemplate: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
			},
			wantErr: "Email Protection",
		},
		{
			name:     "only serverAuth extended key usage",
			spiffeID: testValidSPIFFEID,
			modifyTemplate: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			wantErr: "both serverAuth and clientAuth",
		},
		{
			name:     "CA certificate presented as leaf",
			spiffeID: testValidSPIFFEID,
			modifyTemplate: func(c *x509.Certificate) {
				c.IsCA = true
			},
			wantErr: "cA=false",
		},
		{
			name:       "no URI SAN",
			spiffeID:   "",
			expectedID: testValidSPIFFEID,
			wantErr:    "no URI SANs",
		},
		{
			name:     "more than one URI SAN",
			spiffeID: testValidSPIFFEID,
			modifyTemplate: func(c *x509.Certificate) {
				c.URIs = append(c.URIs, secondURI)
			},
			wantErr: "exactly 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := newSVIDLeafTemplate(t, tt.spiffeID)
			if tt.modifyTemplate != nil {
				tt.modifyTemplate(template)
			}
			cert := signLeaf(t, template, nil)

			// By default the expected name is the same string as the identity
			// carried by the certificate.
			expectedID := tt.expectedID
			if expectedID == "" {
				expectedID = tt.spiffeID
			}

			err := verifyCertificateSVID(cert, expectedID)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

// TestVerifyChainStrictSVID covers the end-to-end strict mode, including the
// trust-path decision against an explicitly supplied CA bundle.
func TestVerifyChainStrictSVID(t *testing.T) {
	fx := newSVIDFixture(t)

	t.Run("conforming chain anchored in explicit CA bundle", func(t *testing.T) {
		leaf := signLeaf(t, newSVIDLeafTemplate(t, testValidSPIFFEID), fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: testValidSPIFFEID,
			CAPath:       fx.caPath,
			StrictSVID:   true,
		})

		assert.Empty(t, result.Error)
		assert.Len(t, result.Chains, 1)
	})

	t.Run("untrusted chain is rejected", func(t *testing.T) {
		// A perfectly conforming SVID issued by a root that is not in the
		// explicit CA bundle must fail path validation.
		leaf := signLeaf(t, newSVIDLeafTemplate(t, testValidSPIFFEID), fx.other)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: testValidSPIFFEID,
			CAPath:       fx.caPath,
			StrictSVID:   true,
		})

		require.NotEmpty(t, result.Error)
		assert.Contains(t, result.Error, "certificate signed by unknown authority")
	})

	t.Run("illegal URI is rejected even though it equals the expected name", func(t *testing.T) {
		const illegalID = "spiffe://Dev.Example.com/path/service"
		leaf := signLeaf(t, newSVIDLeafTemplate(t, illegalID), fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: illegalID,
			CAPath:       fx.caPath,
			StrictSVID:   true,
		})

		require.NotEmpty(t, result.Error)
		// Both strings are identical and malformed: strict mode must reject
		// instead of falling back to a byte-for-byte comparison.
		assert.Contains(t, result.Error, "X.509-SVID identity")
	})

	t.Run("wrong key usage is rejected", func(t *testing.T) {
		template := newSVIDLeafTemplate(t, testValidSPIFFEID)
		template.KeyUsage = x509.KeyUsageKeyEncipherment
		leaf := signLeaf(t, template, fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: testValidSPIFFEID,
			CAPath:       fx.caPath,
			StrictSVID:   true,
		})

		require.NotEmpty(t, result.Error)
		assert.Contains(t, result.Error, "digitalSignature")
	})

	t.Run("identity mismatch is rejected", func(t *testing.T) {
		leaf := signLeaf(t, newSVIDLeafTemplate(t, testValidSPIFFEID), fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: "spiffe://example.org/path/other",
			CAPath:       fx.caPath,
			StrictSVID:   true,
		})

		require.NotEmpty(t, result.Error)
		assert.Contains(t, result.Error, "not spiffe://example.org/path/other")
	})

	t.Run("requires explicit CA bundle", func(t *testing.T) {
		leaf := signLeaf(t, newSVIDLeafTemplate(t, testValidSPIFFEID), fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: testValidSPIFFEID,
			StrictSVID:   true,
		})

		require.NotEmpty(t, result.Error)
		assert.Contains(t, result.Error, "explicit CA bundle")
	})

	t.Run("requires a SPIFFE expected name", func(t *testing.T) {
		leaf := signLeaf(t, newSVIDLeafTemplate(t, testValidSPIFFEID), fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: "example.org",
			CAPath:       fx.caPath,
			StrictSVID:   true,
		})

		require.NotEmpty(t, result.Error)
		assert.Contains(t, result.Error, "not a SPIFFE ID")
	})

	t.Run("malformed expected SPIFFE ID is rejected", func(t *testing.T) {
		leaf := signLeaf(t, newSVIDLeafTemplate(t, testValidSPIFFEID), fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: "spiffe://Example.ORG",
			CAPath:       fx.caPath,
			StrictSVID:   true,
		})

		require.NotEmpty(t, result.Error)
		assert.Contains(t, result.Error, "not a valid leaf X.509-SVID identity")
	})
}

// TestVerifyChainLooseModeCompatibility pins the pre-existing, non-strict
// behavior: SPIFFE matching stays a plain string comparison and regular DNS
// verification is untouched.
func TestVerifyChainLooseModeCompatibility(t *testing.T) {
	fx := newSVIDFixture(t)

	t.Run("valid SVID still passes loose SPIFFE matching", func(t *testing.T) {
		leaf := signLeaf(t, newSVIDLeafTemplate(t, testValidSPIFFEID), fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: testValidSPIFFEID,
			CAPath:       fx.caPath,
		})

		assert.Empty(t, result.Error)
		assert.Len(t, result.Chains, 1)
	})

	t.Run("malformed but byte-equal SPIFFE ID passes in loose mode", func(t *testing.T) {
		// Strict mode rejects this certificate; loose mode only compares the
		// expected and actual strings and therefore accepts it.
		const illegalID = "spiffe://Dev.Example.com/path/service"
		leaf := signLeaf(t, newSVIDLeafTemplate(t, illegalID), fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: illegalID,
			CAPath:       fx.caPath,
		})

		assert.Empty(t, result.Error)
	})

	t.Run("loose SPIFFE mismatch is still rejected", func(t *testing.T) {
		leaf := signLeaf(t, newSVIDLeafTemplate(t, testValidSPIFFEID), fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: "spiffe://example.org/path/other",
			CAPath:       fx.caPath,
		})

		require.NotEmpty(t, result.Error)
		assert.Contains(t, result.Error, "not spiffe://example.org/path/other")
	})

	t.Run("regular DNS verification still works", func(t *testing.T) {
		template := newSVIDLeafTemplate(t, "")
		template.DNSNames = []string{"localhost"}

		leaf := signLeaf(t, template, fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: "localhost",
			CAPath:       fx.caPath,
		})

		assert.Empty(t, result.Error)
		assert.Len(t, result.Chains, 1)
	})

	t.Run("regular DNS mismatch is still rejected", func(t *testing.T) {
		template := newSVIDLeafTemplate(t, "")
		template.DNSNames = []string{"localhost"}

		leaf := signLeaf(t, template, fx.trusted)

		result := VerifyChain([]*x509.Certificate{leaf}, nil, VerifyOptions{
			ExpectedName: "example.com",
			CAPath:       fx.caPath,
		})

		require.NotEmpty(t, result.Error)
	})
}
