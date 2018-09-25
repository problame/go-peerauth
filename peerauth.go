// Package peerauth implements utility functions for TLS peer authentication.
//
// Peer Authentication vs Client Authentication
//
// TLS client authentication is a mechanism to ensure authenticated and encrypted communication between a client
// and a server.
//
// The client verifies the signer of the server's certificate against its trusted certificate authority pool (RootCA pool).
// If the server's certificate was signed by a trusted RootCA, the client will usually validate the certificate's
// CommonName and SubjectAlternativeName.
//
// To authenticate the client towards the server, the client presents a certificate signed by a ClientCA,
// and the server checks if that ClientCA is in the server's trusted ClientCAs pool.
// If so, the server can base further policy decisions on the information contained in the client's certificate,
// e.g. from the CommonName field.
//
// However, situation exist in which no centrally trusted authorities like the RootCA or ClientCA exist,
// and other TLS functionality like centralized revocation, etc., is not required.
// In those cases, it may be desirable to avoid the burden of managing a CA, and use TLS peer authentication instead.
//
// Key Generation
//
// Each node generates a key-pair and a self-signs a certificate containing the public key with its private key.
// An out-of-band mechanism is then used to distribute the certificates of each node to each other.
//
// Mutual Authentication
//
// A server S that wishes to accept connections from a node N adds N's certificate to its client certificate pool.
// A client C that wishes to connect to a server S adds S's certificate to its root CA pool.
// Under the assumption that keypairs are never shared, this configuration authenticates server to client and client to server.
package peerauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"time"
)

type GeneratorArgs struct {
	// The CommonName in the certificate.
	CommonName string
	// The validity dates of the certificate.
	NotBefore, NotAfter time.Time
}

func (a *GeneratorArgs) Validate() error {
	if a.CommonName == "" {
		return fmt.Errorf("CommonName is not set")
	}
	if a.NotBefore.IsZero() {
		return fmt.Errorf("NotBefore is not set")
	} else if a.NotAfter.IsZero() {
		return fmt.Errorf("NotAfter is not set")
	} else if a.NotAfter.Before(a.NotBefore) {
		return fmt.Errorf("NotAfter is before NotBefore")
	}
	return nil
}

// A Generator produces a keypair + certificate encoded in PEM format, parametrized by GeneratorArgs.
type Generator func(args GeneratorArgs) (certPEM, keyPEM []byte, err error)

var (
	// RSA4096 generates a 4096bit RSA keypair + certificate.
	RSA096 Generator = rsa4096
)

func rsa4096(args GeneratorArgs) (certPEM, keyPEM []byte, err error) {

	if err := args.Validate(); err != nil {
		return nil, nil, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: args.CommonName,
		},
		NotBefore: args.NotBefore,
		NotAfter:  args.NotAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certPEMBuf, keyPEMBuf := bytes.Buffer{}, bytes.Buffer{}
	certPEMBlock := pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	if err := pem.Encode(&certPEMBuf, &certPEMBlock); err != nil {
		return nil, nil, err
	}

	keyPEMBlock := pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	if err := pem.Encode(&keyPEMBuf, &keyPEMBlock); err != nil {
		return nil, nil, err
	}

	return certPEMBuf.Bytes(), keyPEMBuf.Bytes(), nil
}

// GenerateFiles generates a keypair + certificate with the given generator and writes the generated PEM
// data out to `outpathStem + {.crt,.key}` with restrictive permissions (0444,0400).
// It does not overwrite files, and rolls back (=removes) files it generated if one write fails.
// Remove failures are silently ignored.
func GenerateFiles(g Generator, args GeneratorArgs, outpathStem string) (crtPath, keyPath string, err error) {

	if err := args.Validate(); err != nil {
		return "", "", err
	}
	if outpathStem == "" {
		return "", "", fmt.Errorf("given output path must not be empty")
	}
	stat, err := os.Stat(outpathStem)
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}
	if err == nil && stat.IsDir() {
		return "", "", fmt.Errorf("given output path must be a directory")
	}
	basename := path.Base(outpathStem)
	if basename == "." || basename == "" {
		return "", "", fmt.Errorf("implementation error: output path must not be a directory")
	}

	var outs writeJobs = []*writeJob{
		newWriteJob(outpathStem+".crt", 0444),
		newWriteJob(outpathStem+".key", 0400),
	}
	if err := outs.Open(); err != nil {
		return "", "", err
	}
	defer outs.Close()

	cert, key, err := g(args)
	if err != nil {
		return "", "", err
	}
	outs[0].SetWriteData(cert)
	outs[1].SetWriteData(key)

	if err := outs.WriteOut(); err != nil {
		return "", "", err
	}
	return outs[0].Path(), outs[1].Path(), nil
}

func loadCertKeyRemotes(cert, key string, remotes []string) (local tls.Certificate, pool *x509.CertPool, err error) {
	local, err = tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return local, nil, err
	}

	remoteCerts := x509.NewCertPool()
	for _, r := range remotes {
		remoteCertPEM, err := ioutil.ReadFile(r)
		if err != nil {
			return local, nil, err
		}
		if !remoteCerts.AppendCertsFromPEM(remoteCertPEM) {
			return local, nil, fmt.Errorf("cannot decode PEM-encoded certificate %q", r)
		}
	}

	return local, remoteCerts, nil
}

// TLSConfigServer generates a *tls.Config for peer authentication.
// All arguments specify paths to PEM-encoded files, e.g. generated by one of this package's Generators.
//
// `cert` is the certificate of the server, `key` is the corresponding private key.
// Each entry in `remotes` is a path to an acceptable certificate of a client.
func TLSConfigServer(cert, key string, remotes []string) (*tls.Config, error) {
	local, clientCA, err := loadCertKeyRemotes(cert, key, remotes)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ClientCAs:    clientCA,
		Certificates: []tls.Certificate{local},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

func TLSConfigClient(cert, key, remote string) (*tls.Config, error) {
	local, remoteCert, err := loadCertKeyRemotes(cert, key, []string{remote})
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RootCAs:      remoteCert,
		Certificates: []tls.Certificate{local},
	}, nil
}
