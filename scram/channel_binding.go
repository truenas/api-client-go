// SPDX-License-Identifier: LGPL-3.0-or-later

package scram

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"hash"
)

// ComputeTLSServerEndPoint computes the RFC 5929 tls-server-end-point channel
// binding for a DER-encoded certificate (ports
// py_scram.compute_tls_server_end_point / the truenas_scram C library).
//
// The binding is the certificate hashed with the digest from its own
// signature algorithm, with MD5 and SHA-1 promoted to SHA-256 (RFC 5929 4.1).
// Signature algorithms with no single well-defined hash (e.g. EdDSA) are
// rejected.
func ComputeTLSServerEndPoint(certDER []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("scram: tls-server-end-point: parsing certificate: %w", err)
	}

	var digest hash.Hash
	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		// RFC 5929 4.1: MD5 and SHA-1 signature hashes are promoted to SHA-256.
		digest = sha256.New()
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		digest = sha256.New()
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		digest = sha512.New384()
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		digest = sha512.New()
	default:
		return nil, fmt.Errorf("scram: tls-server-end-point is undefined for signature algorithm %v",
			cert.SignatureAlgorithm)
	}

	digest.Write(certDER)
	return digest.Sum(nil), nil
}
