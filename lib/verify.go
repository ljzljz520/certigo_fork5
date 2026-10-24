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
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

type simpleVerifyCert struct {
	Name               string `json:"name"`
	IsSelfSigned       bool   `json:"is_self_signed"`
	PEM                string `json:"pem"`
	signatureAlgorithm x509.SignatureAlgorithm
}

type SimpleVerification struct {
	Error          string               `json:"error,omitempty"`
	OCSPStatus     *ocsp.Response       `json:"ocsp_response,omitempty"`
	OCSPWasStapled bool                 `json:"ocsp_was_stapled,omitempty"`
	OCSPError      string               `json:"ocsp_error,omitempty"`
	Chains         [][]simpleVerifyCert `json:"chains"`
}

type SimpleResult struct {
	Certificates           []*x509.Certificate `json:"certificates"`
	Formats                []string
	VerifyResult           *SimpleVerification `json:"verify_result,omitempty"`
	TLSConnectionState     *tls.ConnectionState
	CertificateRequestInfo *tls.CertificateRequestInfo
}

func (s SimpleResult) MarshalJSON() ([]byte, error) {
	certs := make([]interface{}, len(s.Certificates))
	for i, c := range s.Certificates {
		certs[i] = EncodeX509ToObject(c)
	}

	out := map[string]interface{}{}
	out["certificates"] = certs
	if s.VerifyResult != nil {
		out["verify_result"] = s.VerifyResult
	}
	if s.TLSConnectionState != nil {
		out["tls_connection"] = EncodeTLSToObject(s.TLSConnectionState)
	}
	if s.CertificateRequestInfo != nil {
		encoded, err := EncodeCRIToObject(s.CertificateRequestInfo)
		if err != nil {
			return nil, err
		}
		out["certificate_request_info"] = encoded
	}
	return json.Marshal(out)
}

func caBundle(caPath string) (*x509.CertPool, error) {
	if caPath == "" {
		return nil, nil
	}

	caFile, err := os.Open(caPath)
	if err != nil {
		return nil, fmt.Errorf("error opening CA bundle %s: %w", caPath, err)
	}

	bundle := x509.NewCertPool()
	err = ReadAsX509FromFiles(
		[]*os.File{caFile},
		"",
		func(prompt string) string {
			// TODO: The JDK trust store ships with this password.
			return "changeit"
		},
		func(cert *x509.Certificate, format string, err error) error {
			if err != nil {
				return fmt.Errorf("error parsing CA bundle: %w", err)
			} else {
				bundle.AddCert(cert)
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("error parsing CA bundle: %w", err)
	}
	return bundle, nil
}

// VerifyOptions controls how VerifyChain validates a certificate chain.
type VerifyOptions struct {
	// ExpectedName is the DNS name or SPIFFE ID (spiffe://...) that the leaf
	// certificate is expected to carry.
	ExpectedName string
	// CAPath is the path to the CA bundle to trust. When empty, the system
	// default trust store is used.
	CAPath string
	// StrictSVID enables strict X.509-SVID validation. It only applies when
	// ExpectedName is a SPIFFE ID. In this mode:
	//   - CAPath is required, so the trust decision is anchored exclusively in
	//     the explicitly supplied CA bundle rather than the system trust store,
	//   - the leaf certificate must carry exactly one syntactically valid
	//     SPIFFE URI SAN (with a non-root path) matching ExpectedName,
	//   - the leaf certificate must conform to the X.509-SVID leaf profile:
	//     cA=false, a critical key usage setting digitalSignature but not
	//     keyCertSign/cRLSign, and - when present - only serverAuth/clientAuth
	//     extended key usages.
	//
	// A malformed SPIFFE identity is rejected even if it is a byte-for-byte
	// match for ExpectedName.
	StrictSVID bool
}

func VerifyChain(certs []*x509.Certificate, ocspStaple []byte, opts VerifyOptions) SimpleVerification {
	result := SimpleVerification{
		Chains:         [][]simpleVerifyCert{},
		OCSPWasStapled: ocspStaple != nil,
	}

	if len(certs) == 0 {
		result.Error = "no certificates found"
		return result
	}

	spiffeIDExpected := strings.HasPrefix(strings.ToLower(opts.ExpectedName), "spiffe://")

	if opts.StrictSVID {
		if !spiffeIDExpected {
			result.Error = fmt.Sprintf(
				"strict X.509-SVID verification requires a SPIFFE ID, but expected name %q is not a SPIFFE ID",
				opts.ExpectedName)
			return result
		}
		if opts.CAPath == "" {
			result.Error = "strict X.509-SVID verification requires an explicit CA bundle (specify one with --ca)"
			return result
		}
		if _, err := parseLeafSPIFFEID(opts.ExpectedName); err != nil {
			result.Error = fmt.Sprintf("expected SPIFFE ID %q is not a valid leaf X.509-SVID identity: %s", opts.ExpectedName, err)
			return result
		}
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	roots, err := caBundle(opts.CAPath)
	if err != nil {
		result.Error = err.Error() + "\n"
		return result
	}
	// expectedName could be a hostname or could be a SPIFFE ID (spiffe://...)
	// x509 package doesn't support verifying SPIFFE IDs. When we're expecting a SPIFFE ID, we tell
	// Certificate.Verify below to skip name matching, and then we perform our own matching later
	// on.
	var expectedDNSName string
	if !spiffeIDExpected {
		expectedDNSName = opts.ExpectedName
	}
	verifyOpts := x509.VerifyOptions{
		DNSName:       expectedDNSName,
		Roots:         roots,
		Intermediates: intermediates,
	}
	if opts.StrictSVID {
		// The SVID extended key usage rules are enforced explicitly below once
		// the trust path is built, so don't let path validation apply its
		// default TLS server-auth EKU policy.
		verifyOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	chains, err := certs[0].Verify(verifyOpts)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	if spiffeIDExpected {
		// The Verify method above didn't actually verify that the certificate matches the expected
		// SPIFFE ID. We thus perform this check explicitly here.
		if opts.StrictSVID {
			err = verifyCertificateSVID(certs[0], opts.ExpectedName)
		} else {
			err = verifyCertificateSPIFFEIDMatch(certs[0], opts.ExpectedName)
		}
		if err != nil {
			result.Error = err.Error()
			return result
		}
	}

	for _, chain := range chains {
		status, err := checkOCSP(chain, ocspStaple)
		if err == nil {
			result.OCSPStatus = status
		}
		if err != nil && !errors.Is(err, errSkippedRevocationCheck) {
			result.OCSPError = err.Error()
		}

		aChain := []simpleVerifyCert{}
		for _, cert := range chain {
			aCert := simpleVerifyCert{
				IsSelfSigned:       IsSelfSigned(cert),
				signatureAlgorithm: cert.SignatureAlgorithm,
				PEM:                string(pem.EncodeToMemory(EncodeX509ToPEM(cert, nil))),
			}

			aCert.Name = PrintCommonName(cert.Subject)
			aChain = append(aChain, aCert)
		}
		result.Chains = append(result.Chains, aChain)
	}
	return result
}

func fmtCert(cert simpleVerifyCert) string {
	name := cert.Name
	if cert.IsSelfSigned {
		name += green.SprintfFunc()(" [self-signed]")
	}
	for _, alg := range badSignatureAlgorithms {
		if cert.signatureAlgorithm == alg {
			name += red.SprintfFunc()(" [%s]", algString(alg))
			break
		}
	}
	return name
}

func PrintVerifyResult(out io.Writer, result SimpleVerification) {
	if result.Error != "" {
		_, _ = fmt.Fprint(out, red.SprintlnFunc()("Failed to verify certificate chain:"))
		_, _ = fmt.Fprintf(out, "\t%s\n", result.Error)
		return
	}

	printOCSPStatus(out, result)
	printCertificateChains(out, result)
}

func printCertificateChains(out io.Writer, result SimpleVerification) {
	_, _ = fmt.Fprint(out, green.SprintfFunc()("Found %d valid certificate chain(s):\n", len(result.Chains)))
	for i, chain := range result.Chains {
		_, _ = fmt.Fprintf(out, "[%d] %s\n", i, fmtCert(chain[0]))
		for j, cert := range chain {
			if j == 0 {
				continue
			}
			_, _ = fmt.Fprintf(out, "\t=> %s\n", fmtCert(cert))
		}
	}
}

func printOCSPStatus(out io.Writer, result SimpleVerification) {
	if result.OCSPError != "" {
		_, _ = fmt.Fprint(out, red.SprintlnFunc()("Certificate has OCSP extension, but was unable to check status:"))
		_, _ = fmt.Fprintf(out, "\t%s\n\n", result.OCSPError)
		return
	}

	if result.OCSPStatus != nil {
		status, ok := revocationStatusDescription[result.OCSPStatus.Status]
		if !ok {
			status = "Unknown"
		}

		color, ok := revocationStatusColor[result.OCSPStatus.Status]
		if !ok {
			color = yellow
		}

		wasStapled := ""
		if result.OCSPWasStapled {
			wasStapled = " (was stapled)"
		}

		_, _ = fmt.Fprint(out, color.SprintfFunc()("Checked OCSP status for certificate%s, got:", wasStapled))
		_, _ = fmt.Fprintf(out, "\n\t%s (last update: %s)", status, result.OCSPStatus.ProducedAt.Format(time.RFC822))

		if result.OCSPStatus.Status == ocsp.Revoked {
			reason, ok := revocationReasonDescription[result.OCSPStatus.RevocationReason]
			if !ok {
				reason = "Unknown"
			}

			_, _ = fmt.Fprintf(out, "\n\tWas revoked at %s due to: %s", result.OCSPStatus.RevokedAt.Format(time.RFC822), reason)
		}

		_, _ = fmt.Fprint(out, "\n\n")
	}
}

func verifyCertificateSPIFFEIDMatch(cert *x509.Certificate, expectedSPIFFEID string) error {
	// Based on https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
	uris := cert.URIs
	if len(uris) == 0 {
		return fmt.Errorf("x509: cannot validate certificate for %s, because it contains no URI SANs", expectedSPIFFEID)
	} else if len(uris) > 1 {
		return fmt.Errorf("x509: cannot validate certificate for %s, because it contains %d URIs SANs instead of exactly 1", expectedSPIFFEID, len(uris))
	}

	uri := uris[0]
	actualSPIFFEID := uri.String()
	err := verifySPIFFEIDMatch(expectedSPIFFEID, actualSPIFFEID)
	if err != nil {
		return fmt.Errorf("x509: certificate is valid for %s, not %s: %s", actualSPIFFEID, expectedSPIFFEID, err)
	}

	// Matched
	return nil
}

func verifySPIFFEIDMatch(expected string, actual string) error {
	// Based on https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
	// SPIFFE ID format: spiffe://trust-domain-name/path
	// * scheme and authority of the URI are case-insensitive
	// * path of the URI is case-sensitive
	//
	// However, as per Trust Domain and Path sections, authority is not supposed to include userinfo
	// and authority's host is supposed to be lower-case and no %-escaped characters. Similarly, no
	// %-escaped stuff in the path.
	//
	// Thus, all we need to do is verify that:
	// 1. both IDs start with "spiffe://" (case-insensitive)
	// 2. both IDs equal (case-sensitive) after the "spiffe://"

	// Verify both have "spiffe" as the scheme (case-insensitive)
	if !strings.HasPrefix(strings.ToLower(expected), "spiffe://") {
		return fmt.Errorf("expected scheme is not \"spiffe\"")
	}
	if !strings.HasPrefix(strings.ToLower(actual), "spiffe://") {
		return fmt.Errorf("actual scheme is not \"spiffe\"")
	}

	// Verify that everything after the scheme equals in a case-sensitive way
	expectedRemainder := expected[len("spiffe://"):]
	actualRemainder := actual[len("spiffe://"):]
	if expectedRemainder != actualRemainder {
		return fmt.Errorf("trust domain and/or path do not match")
	}

	// They match
	return nil
}

// oidExtensionKeyUsage is the X.509 keyUsage extension OID (2.5.29.15).
var oidExtensionKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

const maxSPIFFEIDLength = 2048
const maxSPIFFETrustDomainLength = 255

// parseLeafSPIFFEID parses raw as a SPIFFE ID carried by an X.509-SVID leaf
// certificate and enforces the SPIFFE identity grammar together with the
// leaf-specific requirement of a non-root path component.
//
// Based on:
//   - https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
//   - https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
//
// A SPIFFE ID consists of the "spiffe" scheme, a non-empty lowercase trust
// domain (only a-z, 0-9, '.', '-' and '_') without userinfo, port or
// percent-encoding, and no query or fragment component. Leaf SVIDs must
// additionally carry a path with at least one non-empty, non-relative segment
// made up of letters, digits, '.', '-' and '_'.
func parseLeafSPIFFEID(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("SPIFFE ID is empty")
	}
	if len(raw) > maxSPIFFEIDLength {
		return nil, fmt.Errorf("SPIFFE ID exceeds the maximum length of %d bytes", maxSPIFFEIDLength)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("SPIFFE ID is not a valid URI: %w", err)
	}
	if u.Scheme != "spiffe" {
		return nil, fmt.Errorf("SPIFFE ID scheme must be \"spiffe\"")
	}
	if u.User != nil {
		return nil, fmt.Errorf("SPIFFE ID trust domain must not contain userinfo")
	}
	if u.Port() != "" {
		return nil, fmt.Errorf("SPIFFE ID trust domain must not contain a port")
	}

	host := u.Host
	if host == "" {
		return nil, fmt.Errorf("SPIFFE ID trust domain must not be empty")
	}
	if len(host) > maxSPIFFETrustDomainLength {
		return nil, fmt.Errorf("SPIFFE ID trust domain must not exceed %d bytes", maxSPIFFETrustDomainLength)
	}
	for _, r := range host {
		if isSPIFFETrustDomainRune(r) {
			continue
		}
		return nil, fmt.Errorf("SPIFFE ID trust domain %q contains invalid character %q (allowed characters are a-z, 0-9, '.', '-' and '_')", host, r)
	}

	if u.RawQuery != "" {
		return nil, fmt.Errorf("SPIFFE ID must not contain a query component")
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("SPIFFE ID must not contain a fragment component")
	}

	// Percent-encoding is forbidden in both the trust domain and the path.
	if strings.Contains(raw, "%") {
		return nil, fmt.Errorf("SPIFFE ID must not contain percent-encoded characters")
	}

	// X.509-SVID leaf certificates MUST have a non-root path component.
	path := u.Path
	if path == "" {
		return nil, fmt.Errorf("leaf X.509-SVID SPIFFE ID must have a non-root path component")
	}
	if strings.HasSuffix(path, "/") {
		return nil, fmt.Errorf("SPIFFE ID path must not have a trailing slash")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		switch segment {
		case "":
			return nil, fmt.Errorf("SPIFFE ID path must not contain empty segments")
		case ".", "..":
			return nil, fmt.Errorf("SPIFFE ID path must not contain relative path segments %q", segment)
		}
		for _, r := range segment {
			if isSPIFFEPathRune(r) {
				continue
			}
			return nil, fmt.Errorf("SPIFFE ID path contains invalid character %q (allowed characters are letters, digits, '.', '-' and '_')", r)
		}
	}

	return u, nil
}

func isSPIFFETrustDomainRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_'
}

func isSPIFFEPathRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '.' || r == '-' || r == '_'
}

// verifyCertificateSVID applies strict X.509-SVID leaf validation on top of
// standard X.509 path validation (see section 5.2 of the X.509-SVID
// specification). The certificate must:
//   - carry exactly one syntactically valid SPIFFE URI SAN matching the
//     expected SPIFFE ID (an identity that is malformed is rejected even when
//     it is a byte-for-byte match for the expected ID),
//   - be a leaf certificate: the basic constraints extension must be present
//     with cA=false,
//   - carry a critical key usage extension setting digitalSignature and not
//     setting keyCertSign/cRLSign,
//   - when an extended key usage extension is present, set both serverAuth and
//     clientAuth and no other key purpose.
func verifyCertificateSVID(cert *x509.Certificate, expectedSPIFFEID string) error {
	// Section 2: an X.509 SVID MUST contain exactly one URI SAN.
	if len(cert.URIs) == 0 {
		return fmt.Errorf("x509: cannot validate certificate for %s, because it contains no URI SANs", expectedSPIFFEID)
	}
	if len(cert.URIs) > 1 {
		return fmt.Errorf("x509: cannot validate certificate for %s, because it contains %d URI SANs instead of exactly 1", expectedSPIFFEID, len(cert.URIs))
	}

	// The identity is validated on its own merits first: a syntactically
	// illegal SPIFFE URI does not become acceptable merely because the caller
	// happens to expect the same string.
	actualID := cert.URIs[0].String()
	actual, err := parseLeafSPIFFEID(actualID)
	if err != nil {
		return fmt.Errorf("x509: certificate carries SPIFFE ID %q which is not a valid X.509-SVID identity: %s", actualID, err)
	}
	expected, err := parseLeafSPIFFEID(expectedSPIFFEID)
	if err != nil {
		return fmt.Errorf("x509: expected SPIFFE ID %q is not a valid X.509-SVID identity: %s", expectedSPIFFEID, err)
	}
	// Scheme and trust domain are case-insensitive (the grammar requires
	// lowercase hosts), while the path is case-sensitive.
	if !strings.EqualFold(actual.Host, expected.Host) || actual.Path != expected.Path {
		return fmt.Errorf("x509: certificate is valid for %s, not %s", actualID, expectedSPIFFEID)
	}

	// Sections 4.1 and 5.2: leaf SVIDs MUST set cA=false.
	if !cert.BasicConstraintsValid || cert.IsCA {
		return fmt.Errorf("x509: SVID leaf certificate must include the basic constraints extension with cA=false")
	}

	// Section 4.3: the key usage extension MUST be present and marked
	// critical. Leaf SVIDs MUST set digitalSignature and MUST NOT set
	// keyCertSign or cRLSign.
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("x509: SVID leaf certificate key usage must set digitalSignature")
	}
	if cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return fmt.Errorf("x509: SVID leaf certificate key usage must not set keyCertSign or cRLSign")
	}
	if present, critical := findKeyUsageExtension(cert); !present {
		return fmt.Errorf("x509: SVID leaf certificate must include the key usage extension")
	} else if !critical {
		return fmt.Errorf("x509: SVID leaf certificate key usage extension must be marked critical")
	}

	// Section 4.4: when present, EKU MUST set both serverAuth and clientAuth
	// and MUST NOT contain any other key purpose.
	if len(cert.ExtKeyUsage) > 0 || len(cert.UnknownExtKeyUsage) > 0 {
		var hasServerAuth, hasClientAuth bool
		for _, usage := range cert.ExtKeyUsage {
			switch usage {
			case x509.ExtKeyUsageServerAuth:
				hasServerAuth = true
			case x509.ExtKeyUsageClientAuth:
				hasClientAuth = true
			default:
				name, ok := extKeyUsageStrings[usage]
				if !ok {
					name = fmt.Sprintf("extended key usage %d", usage)
				}
				return fmt.Errorf("x509: SVID leaf certificate extended key usage must only contain serverAuth and clientAuth, but certificate is valid for %s", name)
			}
		}
		if len(cert.UnknownExtKeyUsage) > 0 {
			return fmt.Errorf("x509: SVID leaf certificate extended key usage must only contain serverAuth and clientAuth, but certificate is valid for unknown key purpose %s", cert.UnknownExtKeyUsage[0].String())
		}
		if !hasServerAuth || !hasClientAuth {
			return fmt.Errorf("x509: SVID leaf certificate extended key usage must set both serverAuth and clientAuth")
		}
	}

	return nil
}

func findKeyUsageExtension(cert *x509.Certificate) (present bool, critical bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtensionKeyUsage) {
			return true, ext.Critical
		}
	}
	return false, false
}
