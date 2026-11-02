package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	// https://android.googleapis.com/attestation/root
	// https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
	attestationRoots = `[
  "-----BEGIN CERTIFICATE-----\nMIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\nBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw\nNzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B\nAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS\nSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7\ntv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj\nnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq\nC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ\noVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O\nJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg\nsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi\nigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M\nRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E\naDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um\nAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud\nIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD\nVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7\n174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC\nW/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G\ntkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx\noSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG\n1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF\nmr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz\nlHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw\nn6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu\nzbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo\nvaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn\nw1IdYIg2Wxg7yHcQZemFQg==\n-----END CERTIFICATE-----",
  "-----BEGIN CERTIFICATE-----\nMIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc\nMBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET\nMBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4\nWhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex\nMRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG\nEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt\nG/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5\nEczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB\n/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA\nMAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH\nEUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY\nuR2zh/80lQyu9vAFCj6E4AXc+osmRg==\n-----END CERTIFICATE-----"
]`
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <path/to/file.bin>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	targetPath := os.Args[1]
	log.Printf("Reading %s, this can take a while for large files...\n", targetPath)
	result, err := AnalyzeBinary(targetPath)
	if err != nil {
		log.Fatalf("Failed to analyze %s: %v", targetPath, err)
	}
	log.Println(result.String())

	foundGoogleCert := false
	googleRoots, err := loadGoogleAttestationRoots()
	if err != nil {
		log.Fatal("Failed to load google attestation roots", err)
	}

	for _, chain := range result.Chains {
		if chain.ChainsToGoogleRoot(googleRoots) {
			foundGoogleCert = true
			break
		}
	}

	if !foundGoogleCert {
		log.Fatalf("Keybox not found in file")
	}
	log.Println("EXTRACTED KEYBOX! Checking revocation list...")
	crl, err := loadRevocationList()
	if err != nil {
		// In the case of no internet, allow dump to continue without CRL checks
		log.Printf("Failed to load revocation list, revocation checks are disabled: %v", err)
	}
	serials := []string{}
	revoked := false
	for _, chain := range result.Chains {
		if chain.ChainsToGoogleRoot(googleRoots) {
			for _, cert := range chain.Certs {
				serial := cert.Cert.SerialNumber.Text(16)
				serials = append(serials, serial)
				if err == nil {
					if revocation, found := crl.Entries[serial]; found {
						log.Printf("Found serial %s on revocation list: %+v\n", serial, revocation)
						revoked = true
					}
				}
			}
		}
	}
	log.Println("Reconstructing keybox.xml...")
	var androidKeys []AndroidKey

	for _, chain := range result.Chains {
		if chain.ChainsToGoogleRoot(googleRoots) {
			privateKey := AndroidPrivateKey{
				Format: "pem",
				Data:   string(orPanic(PrivateKeyToPEM(chain.PrivateKey))),
			}
			var certificates []AndroidCertificate
			for _, cert := range chain.Certs {
				certificates = append(certificates, AndroidCertificate{
					Format: "pem",
					Data:   string(orPanic(CertToPEM(cert.Cert))),
				})
			}

			switch chain.KeyType {
			case "rsa", "ecdsa":
				androidKeys = append(androidKeys, AndroidKey{
					Algorithm:  chain.KeyType,
					PrivateKey: privateKey,
					CertificateChain: AndroidCertificateChain{
						NumberOfCertificates: len(chain.Certs),
						Certificates:         certificates,
					},
				})
			default:
				log.Println("Unrecognized key type:", chain.KeyType)
			}
		}
	}

	keybox := AndroidAttestation{
		NumberOfKeyboxes: 1,
		Keyboxes: []AndroidKeybox{
			{
				Keys:     androidKeys,
				DeviceID: "bluesmods.com",
			},
		},
	}

	// Write to file keybox_SERIAL.xml

	f := orPanic(os.OpenFile(fmt.Sprintf("keybox_%s.xml", serials[0]), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666))
	defer f.Close()

	_, _ = f.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	_, _ = f.WriteString("<!--\n")
	_, _ = f.WriteString("Extracted by https://github.com/bluemods/android-keybox-extractor\n")
	_, _ = f.WriteString(fmt.Sprintf("Serials: %s\n", strings.Join(serials, ", ")))
	_, _ = f.WriteString(fmt.Sprintf("Revoked: %t\n", revoked))
	_, _ = f.WriteString(fmt.Sprintf("Checked At: %s\n", time.Now().UTC().String()))
	_, _ = f.WriteString("-->\n")
	enc := xml.NewEncoder(f)
	defer enc.Flush()
	enc.Indent("", "  ")
	_ = enc.Encode(keybox)

	if !revoked {
		log.Println("Keybox is not revoked!")
	} else {
		log.Println("WARNING: Keybox is REVOKED - this means that other services will usually NOT trust it, and you probably shouldn't use it. Dumping anyway...")
	}

	log.Printf("Written to %s\n", f.Name())
}

func loadRevocationList() (AndroidCRLList, error) {
	resp, err := http.Get("https://android.googleapis.com/attestation/status")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	var androidCrlList AndroidCRLList
	return androidCrlList, json.NewDecoder(resp.Body).Decode(&androidCrlList)
}

func loadGoogleAttestationRoots() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var encodedCerts []string
	if err := json.NewDecoder(bytes.NewReader([]byte(attestationRoots))).Decode(&encodedCerts); err != nil {
		return nil, err
	}
	for _, encodedCert := range encodedCerts {
		block, _ := pem.Decode([]byte(encodedCert))
		if block != nil && block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func orPanic[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}
