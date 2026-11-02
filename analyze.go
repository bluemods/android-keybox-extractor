package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// CarvedCert represents an extracted X.509 certificate and its raw location.
type CarvedCert struct {
	Offset int
	Size   int
	Raw    []byte
	Cert   *x509.Certificate
}

func (c CarvedCert) String() string {
	name := c.Cert.Subject.CommonName
	if name == "" {
		name = c.Cert.Subject.String()
	}
	return fmt.Sprintf("Cert @ 0x%06X (Size: %d) - %s [Issuer: %s]", c.Offset, c.Size, name, c.Cert.Issuer.CommonName)
}

// CarvedKey represents an extracted RSA or ECDSA private key.
type CarvedKey struct {
	Offset   int
	Size     int
	Type     string
	Raw      []byte
	RSAKey   *rsa.PrivateKey
	ECDSAKey *ecdsa.PrivateKey
}

// Signer returns a standard crypto.Signer interface if an underlying key exists.
func (k CarvedKey) Signer() crypto.Signer {
	if k.RSAKey != nil {
		return k.RSAKey
	}
	if k.ECDSAKey != nil {
		return k.ECDSAKey
	}
	return nil
}

func (k CarvedKey) String() string {
	bitSize := 0
	if k.RSAKey != nil {
		bitSize = k.RSAKey.N.BitLen()
	} else if k.ECDSAKey != nil {
		bitSize = k.ECDSAKey.Curve.Params().BitSize
	}
	return fmt.Sprintf("Key @ 0x%06X (Size: %d) - %s (%d-bit)", k.Offset, k.Size, k.Type, bitSize)
}

// KeyCertMatch binds a private key directly to the certificate presenting its public key.
type KeyCertMatch struct {
	Key  CarvedKey
	Cert CarvedCert
}

func (m KeyCertMatch) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[+] %s\n", m.Key.String())
	fmt.Fprintf(&b, "    Matches Public Key of: %s\n", m.Cert.String())
	fmt.Fprintf(&b, "    Subject: %s", m.Cert.Cert.Subject)
	return b.String()
}

// SigningRelation models a verified parent-child cryptographic signature link.
type SigningRelation struct {
	Parent     CarvedCert
	Child      CarvedCert
	SelfSigned bool
}

func (r SigningRelation) String() string {
	if r.SelfSigned {
		return fmt.Sprintf("[Self-Signed / Root] %s", r.Child.String())
	}
	return fmt.Sprintf("[Valid Signature] %s\n      └─ Signed ─> %s", r.Parent.String(), r.Child.String())
}

// CertificateChain represents an assembled path from leaf certificate to root,
// including the private key matching either the leaf or signing authority.
type CertificateChain struct {
	KeyType    string            // "rsa", "ecdsa", or "Unknown"
	Certs      []CarvedCert      // Leaf -> Intermediate(s) -> Root
	PrivateKey crypto.PrivateKey // *rsa.PrivateKey or *ecdsa.PrivateKey
	KeyMeta    *CarvedKey        // Pointer to metadata (offset, size, raw bytes)
}

// True if this certificate chain is a TEE chain
// using the Google factory-provisioned trust root.
func (chain CertificateChain) IsTee() bool {
	// See https://developer.android.com/privacy-and-security/security-key-attestation#expired_factory_keys
	return chain.PrivateKey != nil &&
		len(chain.Certs) >= 3 &&
		(chain.KeyType == "rsa" || chain.KeyType == "ecdsa") &&
		chain.Certs[len(chain.Certs)-1].Cert.Subject.String() == "SERIALNUMBER=f92009e853b6b045"
}

// True if this certificate chains to any of the provided googleRootCerts.
// See https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
func (chain CertificateChain) ChainsToGoogleRoot(googleRootCerts []*x509.Certificate) bool {
	if chain.PrivateKey == nil {
		return false
	}
	if len(chain.Certs) < 3 {
		return false
	}
	myKey := chain.Certs[len(chain.Certs)-1].Cert.PublicKey.(interface{ Equal(x crypto.PublicKey) bool })
	for _, googleCert := range googleRootCerts {
		googleKey := googleCert.PublicKey.(interface{ Equal(x crypto.PublicKey) bool })
		if googleKey.Equal(myKey) {
			return true
		}
	}
	return false
}

// Signer returns a crypto.Signer if the underlying private key supports it.
func (chain CertificateChain) Signer() crypto.Signer {
	if s, ok := chain.PrivateKey.(crypto.Signer); ok {
		return s
	}
	return nil
}

func (chain CertificateChain) String() string {
	var b strings.Builder
	keyStatus := "None"
	if chain.KeyMeta != nil {
		keyStatus = chain.KeyMeta.String()
	}
	fmt.Fprintf(&b, "Key Material: %s\n", keyStatus)

	for i, cert := range chain.Certs {
		indent := strings.Repeat("  ", i)
		fmt.Fprintf(&b, "%s└─ [0x%06X] (%s) %s\n", indent, cert.Offset, chain.KeyType, cert.String())
	}
	return strings.TrimRight(b.String(), "\n")
}

// detectKeyType inspects an X.509 certificate to determine its public key algorithm.
func detectKeyType(cert *x509.Certificate) string {
	if cert == nil {
		return "Unknown"
	}
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "rsa"
	case *ecdsa.PublicKey:
		return "ecdsa"
	default:
		return "Unknown"
	}
}

// AnalysisResult contains all structured forensic artifacts and relationship models.
type AnalysisResult struct {
	Certificates []CarvedCert
	PrivateKeys  []CarvedKey
	KeyMatches   []KeyCertMatch
	Relations    []SigningRelation
	Chains       []CertificateChain
}

func (r AnalysisResult) String() string {
	var b strings.Builder

	if len(r.KeyMatches) == 0 {
		b.WriteString("[-] No private keys directly matched any carved certificate.\n")
	} else {
		b.WriteString("==================================================\n")
		b.WriteString("PRIVATE KEY MATCHES\n")
		b.WriteString("==================================================\n")
		for _, m := range r.KeyMatches {
			b.WriteString(m.String() + "\n")
		}
	}

	if len(r.Relations) == 0 {
		b.WriteString("[-] No cryptographic relationships discovered.\n")
	} else {
		b.WriteString("\n==================================================\n")
		b.WriteString("SIGNING RELATIONSHIPS\n")
		b.WriteString("==================================================\n")
		for _, rel := range r.Relations {
			b.WriteString(rel.String() + "\n")
		}
	}

	if len(r.Chains) == 0 {
		b.WriteString("[-] No complete chains resolved.\n")
	} else {
		b.WriteString("\n==================================================\n")
		b.WriteString("RECONSTRUCTED CHAINS (Leaf -> Root)\n")
		b.WriteString("==================================================\n")
		for i, chain := range r.Chains {
			fmt.Fprintf(&b, "Chain %d:\n%s\n\n", i+1, chain.String())
		}
	}

	return b.String()
}

// AnalyzeBinary parses raw storage dumps and extracts structured cryptographic material.
func AnalyzeBinary(filePath string) (*AnalysisResult, error) {
	// Memory-map the input instead of reading it all into the Go heap. Both
	// carve passes need random access over the whole file, and mmap gives that
	// without the resident-memory cost of os.ReadFile on large dumps.
	//
	// The carve functions copy every byte they retain (see carveASN1), so the
	// returned result stays valid after the mapping is released here.
	// TODO: windows support or use random access file
	data, closeData, err := mapFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("mapping input file: %w", err)
	}
	defer func() {
		_ = closeData()
	}()

	certs, keys := carveASN1(data)
	keys = append(keys, carveRawECDSAScalars(data, certs, keys)...)

	result := &AnalysisResult{
		Certificates: certs,
		PrivateKeys:  keys,
	}

	// 1. Key Matching
	for _, k := range keys {
		for _, c := range certs {
			if matchKeyToCert(k, c) {
				result.KeyMatches = append(result.KeyMatches, KeyCertMatch{Key: k, Cert: c})
			}
		}
	}

	// 2. Discover Signing Relations
	parentOf := make(map[int]CarvedCert)
	certMap := make(map[int]CarvedCert)
	for _, c := range certs {
		certMap[c.Offset] = c
	}

	for _, child := range certs {
		for _, parent := range certs {
			if !bytes.Equal(child.Cert.RawIssuer, parent.Cert.RawSubject) {
				continue
			}

			if err := child.Cert.CheckSignatureFrom(parent.Cert); err == nil {
				if child.Offset == parent.Offset {
					result.Relations = append(result.Relations, SigningRelation{
						Child:      child,
						SelfSigned: true,
					})
				} else {
					result.Relations = append(result.Relations, SigningRelation{
						Parent:     parent,
						Child:      child,
						SelfSigned: false,
					})
					parentOf[child.Offset] = parent
				}
			}
		}
	}

	// 3. Assemble Chains
	// 3. Assemble Chains and bind Private Keys
	isParent := make(map[int]bool)
	for _, p := range parentOf {
		isParent[p.Offset] = true
	}

	for _, c := range certs {
		if !isParent[c.Offset] {
			var currentChain []CarvedCert
			curr := c
			visited := make(map[int]bool)

			for {
				currentChain = append(currentChain, curr)
				visited[curr.Offset] = true

				parent, exists := parentOf[curr.Offset]
				if !exists || visited[parent.Offset] {
					break
				}
				curr = parent
			}

			keyType := "Unknown"
			var privKey crypto.PrivateKey
			var keyMeta *CarvedKey

			if len(currentChain) > 0 && currentChain[0].Cert != nil {
				leaf := currentChain[0]
				keyType = detectKeyType(leaf.Cert)

				// Find if any carved private key matches this leaf cert
				for idx := range keys {
					if matchKeyToCert(keys[idx], leaf) {
						keyMeta = &keys[idx]
						if keys[idx].RSAKey != nil {
							privKey = keys[idx].RSAKey
						} else if keys[idx].ECDSAKey != nil {
							privKey = keys[idx].ECDSAKey
						}
						break
					}
				}
			}

			result.Chains = append(result.Chains, CertificateChain{
				KeyType:    keyType,
				Certs:      currentChain,
				PrivateKey: privKey,
				KeyMeta:    keyMeta,
			})
		}
	}

	return result, nil
}

func carveASN1(data []byte) ([]CarvedCert, []CarvedKey) {
	var certs []CarvedCert
	var keys []CarvedKey

	seenCerts := make(map[string]bool)
	limit := len(data)

	for i := 0; i < limit-4; i++ {
		if data[i] != 0x30 {
			continue
		}

		totalLen, ok := parseDERSequenceLength(data[i:])
		if !ok || i+totalLen > limit || totalLen < 64 {
			continue
		}

		block := data[i : i+totalLen]

		if cert, err := x509.ParseCertificate(block); err == nil {
			id := string(cert.Raw)
			if !seenCerts[id] {
				seenCerts[id] = true
				// Re-parse from an owned copy: x509.ParseCertificate keeps
				// cert.Raw aliasing the input, which would dangle once the
				// backing mapping is unmapped.
				raw := bytes.Clone(block)
				if owned, err := x509.ParseCertificate(raw); err == nil {
					cert = owned
				}
				certs = append(certs, CarvedCert{
					Offset: i,
					Size:   totalLen,
					Raw:    raw,
					Cert:   cert,
				})
			}
			i += totalLen - 1
			continue
		}

		if rsaKey, err := x509.ParsePKCS1PrivateKey(block); err == nil {
			keys = append(keys, CarvedKey{
				Offset: i,
				Size:   totalLen,
				Type:   "RSA (PKCS#1)",
				Raw:    bytes.Clone(block),
				RSAKey: rsaKey,
			})
			i += totalLen - 1
			continue
		}

		if ecKey, err := x509.ParseECPrivateKey(block); err == nil {
			keys = append(keys, CarvedKey{
				Offset:   i,
				Size:     totalLen,
				Type:     "ECDSA (SEC1)",
				Raw:      bytes.Clone(block),
				ECDSAKey: ecKey,
			})
			i += totalLen - 1
			continue
		}

		if pk8, err := x509.ParsePKCS8PrivateKey(block); err == nil {
			switch k := pk8.(type) {
			case *rsa.PrivateKey:
				keys = append(keys, CarvedKey{
					Offset: i,
					Size:   totalLen,
					Type:   "RSA (PKCS#8)",
					Raw:    bytes.Clone(block),
					RSAKey: k,
				})
			case *ecdsa.PrivateKey:
				keys = append(keys, CarvedKey{
					Offset:   i,
					Size:     totalLen,
					Type:     "ECDSA (PKCS#8)",
					Raw:      bytes.Clone(block),
					ECDSAKey: k,
				})
			}
			i += totalLen - 1
			continue
		}
	}

	return certs, keys
}

// ecTargetGroup bundles every ECDSA public key that shares a curve, so a single
// scan position needs only one ScalarBaseMult (the expensive operation) checked
// against all candidate public keys on that curve.
type ecTargetGroup struct {
	curve      elliptic.Curve
	name       string
	scalarLen  int
	orderBytes []byte // N as fixed-width big-endian, for allocation-free range checks
	pubs       []*ecdsa.PublicKey
}

// scalarSearchRadius is how far on either side of a carved cert/key offset we
// look for a matching raw ECDSA scalar. Keybox provisioning stores the private
// scalar in close proximity to its certificate, so a bounded window around each
// ASN.1 finding avoids scanning the whole dump.
const scalarSearchRadius = 1 << 20 // 1 MiB

// carveRawECDSAScalars brute-forces the dump for raw private scalars whose
// base-point multiple equals a carved certificate's ECDSA public key.
//
// Rather than sweeping the entire file, the scan is confined to windows of
// ±scalarSearchRadius bytes around every carved certificate and key offset
// (anchors), since the raw scalar is stored next to that material. This turns a
// whole-file brute force into a few small local searches. Within those windows
// it is further optimized versus a naive per-target sweep:
//   - public keys are grouped by curve, so each position does one ScalarBaseMult
//     shared across all targets on that curve (not one sweep per target);
//   - a cheap big-endian range check rejects out-of-order scalars before any
//     big.Int or point multiplication is done;
//   - positions are partitioned across GOMAXPROCS worker goroutines;
//   - the scan stops as soon as every target has been located.
func carveRawECDSAScalars(data []byte, certs []CarvedCert, asn1Keys []CarvedKey) []CarvedKey {
	groups := map[string]*ecTargetGroup{}
	for _, c := range certs {
		ecPub, ok := c.Cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		params := ecPub.Params()
		key := params.N.Text(16) // the order uniquely identifies the curve
		g := groups[key]
		if g == nil {
			scalarLen := (params.BitSize + 7) / 8
			orderBytes := make([]byte, scalarLen)
			params.N.FillBytes(orderBytes)
			g = &ecTargetGroup{
				curve:      ecPub.Curve,
				name:       params.Name,
				scalarLen:  scalarLen,
				orderBytes: orderBytes,
			}
			groups[key] = g
		}
		g.pubs = append(g.pubs, ecPub)
	}
	if len(groups) == 0 {
		return nil
	}

	windows := buildSearchWindows(data, certs, asn1Keys, scalarSearchRadius)
	if len(windows) == 0 {
		return nil
	}

	var keys []CarvedKey
	for _, g := range groups {
		keys = append(keys, scanECGroup(data, g, windows)...)
	}
	return keys
}

// byteWindow is a half-open [lo, hi) range of the dump to search.
type byteWindow struct {
	lo, hi int
}

// buildSearchWindows returns the merged set of byte ranges within
// ±radius of every carved certificate and key offset, clamped to the dump.
// Overlapping ranges are coalesced so clustered findings are scanned once.
func buildSearchWindows(data []byte, certs []CarvedCert, keys []CarvedKey, radius int) []byteWindow {
	n := len(data)
	windows := make([]byteWindow, 0, len(certs)+len(keys))
	add := func(offset, size int) {
		lo := max(offset-radius, 0)
		hi := min(offset+size+radius, n)
		if lo < hi {
			windows = append(windows, byteWindow{lo, hi})
		}
	}
	for _, c := range certs {
		add(c.Offset, c.Size)
	}
	for _, k := range keys {
		add(k.Offset, k.Size)
	}
	if len(windows) == 0 {
		return nil
	}

	sort.Slice(windows, func(i, j int) bool { return windows[i].lo < windows[j].lo })
	merged := windows[:1]
	for _, w := range windows[1:] {
		last := &merged[len(merged)-1]
		if w.lo <= last.hi { // overlapping or adjacent
			if w.hi > last.hi {
				last.hi = w.hi
			}
			continue
		}
		merged = append(merged, w)
	}
	return merged
}

// posInterval maps a contiguous run of 4-byte-aligned candidate offsets into a
// flattened logical index space so workers can partition evenly across windows.
type posInterval struct {
	startPos int // first candidate byte offset (multiple of 4)
	count    int // number of offsets in this interval (step 4)
	cum      int // logical index of startPos in the flattened position space
}

// scanECGroup performs the parallel brute-force scan for a single curve group,
// restricted to the supplied byte windows.
//
//goland:noinspection GoDeprecation
func scanECGroup(data []byte, g *ecTargetGroup, windows []byteWindow) []CarvedKey {
	maxStart := len(data) - g.scalarLen
	if maxStart < 0 {
		return nil
	}

	// Flatten the windows into 4-byte-aligned candidate positions, clamped so
	// every start offset leaves room for a full scalar.
	var intervals []posInterval
	total := 0
	for _, w := range windows {
		startPos := (w.lo + 3) &^ 3 // first multiple of 4 >= w.lo
		upper := min(w.hi, maxStart+1)
		if startPos >= upper {
			continue
		}
		count := (upper-1-startPos)/4 + 1
		intervals = append(intervals, posInterval{startPos: startPos, count: count, cum: total})
		total += count
	}
	if total == 0 {
		return nil
	}

	workers := min(runtime.NumCPU(), total)
	posPerWorker := (total + workers - 1) / workers

	found := make([]int32, len(g.pubs)) // 0 = still searching, 1 = located
	remaining := int32(len(g.pubs))
	results := make([][]CarvedKey, workers)

	var wg sync.WaitGroup
	for w := range workers {
		a := w * posPerWorker // logical [a, b) slice of candidate positions
		if a >= total {
			break
		}
		b := min(a+posPerWorker, total)

		wg.Add(1)
		go func(w, a, b int) {
			defer wg.Done()
			var local []CarvedKey
			checked := 0

		scan:
			for _, iv := range intervals {
				// Intersect this worker's logical range with the interval.
				s := max(iv.cum, a)
				e := min(iv.cum+iv.count, b)
				for li := s; li < e; li++ {
					// Periodically bail out once every target is found.
					if checked&0x3FFF == 0 && atomic.LoadInt32(&remaining) == 0 {
						break scan
					}
					checked++

					i := iv.startPos + (li-iv.cum)*4
					chunk := data[i : i+g.scalarLen]

					// Reject zero and out-of-order scalars without allocating.
					if allZero(chunk) || bytes.Compare(chunk, g.orderBytes) >= 0 {
						continue
					}

					x, y := g.curve.ScalarBaseMult(chunk)
					for ti := range g.pubs {
						if atomic.LoadInt32(&found[ti]) != 0 {
							continue
						}
						pub := g.pubs[ti]
						if x.Cmp(pub.X) != 0 || y.Cmp(pub.Y) != 0 {
							continue
						}
						if !atomic.CompareAndSwapInt32(&found[ti], 0, 1) {
							continue // another worker claimed it first
						}
						atomic.AddInt32(&remaining, -1)
						local = append(local, CarvedKey{
							Offset: i,
							Size:   g.scalarLen,
							Type:   fmt.Sprintf("Raw ECDSA Scalar (%s)", g.name),
							Raw:    bytes.Clone(chunk),
							ECDSAKey: &ecdsa.PrivateKey{
								PublicKey: *pub,
								D:         new(big.Int).SetBytes(chunk),
							},
						})
					}
				}
			}

			results[w] = local
		}(w, a, b)
	}
	wg.Wait()

	var keys []CarvedKey
	for _, r := range results {
		keys = append(keys, r...)
	}
	return keys
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func parseDERSequenceLength(b []byte) (int, bool) {
	if len(b) < 2 || b[0] != 0x30 {
		return 0, false
	}
	if b[1] < 0x80 {
		return int(b[1]) + 2, true
	}
	numBytes := int(b[1] & 0x7F)
	if numBytes == 0 || numBytes > 4 || len(b) < 2+numBytes {
		return 0, false
	}
	length := 0
	for j := range numBytes {
		length = (length << 8) | int(b[2+j])
	}
	return length + 2 + numBytes, true
}

func matchKeyToCert(k CarvedKey, c CarvedCert) bool {
	if k.RSAKey != nil {
		if pub, ok := c.Cert.PublicKey.(*rsa.PublicKey); ok {
			return k.RSAKey.N.Cmp(pub.N) == 0 && k.RSAKey.E == pub.E
		}
	}
	if k.ECDSAKey != nil {
		if pub, ok := c.Cert.PublicKey.(*ecdsa.PublicKey); ok {
			return k.ECDSAKey.X.Cmp(pub.X) == 0 && k.ECDSAKey.Y.Cmp(pub.Y) == 0
		}
	}
	return false
}

func CertToPEM(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, fmt.Errorf("failed to encode certificate to PEM: %w", err)
	}

	return buf.Bytes(), nil
}

// PrivateKeyToPEM marshals RSA (PKCS#1) or ECDSA (SEC 1) into the compatible PEM format.
func PrivateKeyToPEM(priv crypto.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	var blockType string
	var derBytes []byte
	var err error

	switch k := priv.(type) {
	case *rsa.PrivateKey:
		blockType = "RSA PRIVATE KEY"
		derBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		blockType = "EC PRIVATE KEY"
		derBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %T (must be *rsa.PrivateKey or *ecdsa.PrivateKey)", priv)
	}

	block := &pem.Block{
		Type:  blockType,
		Bytes: derBytes,
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, fmt.Errorf("failed to encode private key to PEM: %w", err)
	}

	return buf.Bytes(), nil
}
