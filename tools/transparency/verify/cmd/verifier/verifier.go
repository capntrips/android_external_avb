// Binary `verifier` checks the inclusion of a particular Pixel Factory Image,
// identified by its build_fingerprint and vbmeta_digest (the payload), in the
// Transparency Log.
//
// Inputs to the tool are:
//   - the log leaf index of the image of interest, from the Pixel Binary
//     Transparency Log, see:
//     https://developers.google.com/android/binary_transparency/image_info.txt
//   - the path to a file containing the payload, see this page for instructions
//     https://developers.google.com/android/binary_transparency/pixel#construct-the-payload-for-verification.
//   - the log's base URL, if different from the default provided.
//
// Outputs:
//   - "OK" if the image is included in the log,
//   - "FAILURE" if it isn't.
//
// Usage: See README.md.
// For more details on inclusion proofs, see:
// https://developers.google.com/android/binary_transparency/pixel#verifying-image-inclusion-inclusion-proof
package main

import (
	// Using "flag" and "log" and not their "google3/base/go/" counterparts is
	// intended in order to reduce google3 dependencies. This code will live in
	// https://android.googlesource.com/platform/external/avb/+/master/tools/transparency/.
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/binary_transparency/verifier/internal/checkpoint"
	"github.com/google/binary_transparency/verifier/internal/tiles"
	"golang.org/x/mod/sumdb/tlog"

	_ "embed"
)

// Domain separation prefix for Merkle tree hashing with second preimage
// resistance similar to that used in RFC 6962.
const (
	LeafHashPrefix     = 0
	KeyNameForVerifier = "pixel6_transparency_log"
)

// See https://developers.google.com/android/binary_transparency/pixel#signature-verification.
//go:embed log_pub_key.pem
var logPubKey []byte

var (
	imageInfoIndex = flag.Int64("image_info_index", -1, "Index representing the image of interest within the image_info.txt log file. Must be in the [0, logSize) range.")
	payloadPath    = flag.String("payload_path", "", "Path to the payload describing the image of interest.")
	logBaseURL     = flag.String("log_base_url", "https://developers.google.com/android/binary_transparency", "Base url for the verifiable log files.")
)

func main() {
	flag.Parse()

	if *imageInfoIndex < 0 {
		log.Fatal("must specify the image_info_index, in the [0, logSize) range, for the image of interest")
	}
	if *payloadPath == "" {
		log.Fatal("must specify the payload_path for the image payload")
	}

	v, err := checkpoint.NewVerifier(logPubKey, KeyNameForVerifier)
	if err != nil {
		log.Fatalf("error creating verifier: %v", err)
	}
	root, err := checkpoint.FromURL(*logBaseURL, v)
	if err != nil {
		log.Fatalf("error reading checkpoint for log(%s): %v", *logBaseURL, err)
	}

	logSize := int64(root.Size)
	if *imageInfoIndex >= logSize {
		log.Fatalf("leaf_index must be in the [0, logSize) range: logSize=%d", logSize)
	}
	var th tlog.Hash
	copy(th[:], root.Hash)

	r := tiles.HashReader{URL: *logBaseURL}
	rp, err := tlog.ProveRecord(logSize, *imageInfoIndex, r)
	if err != nil {
		log.Fatalf("error in tlog.ProveRecord: %v", err)
	}

	leafHash, err := payloadHash(*payloadPath)
	if err != nil {
		log.Fatalf("error hashing payload: %v", err)
	}

	if err := tlog.CheckRecord(rp, logSize, th, *imageInfoIndex, leafHash); err != nil {
		log.Fatalf("FAILURE: inclusion check error in tlog.CheckRecord: %v", err)
	} else {
		log.Print("OK. inclusion check success")
	}
}

// payloadHash returns the hash for the payload located at path p.
func payloadHash(p string) (tlog.Hash, error) {
	var hash tlog.Hash
	f, err := os.ReadFile(p)
	if err != nil {
		return hash, fmt.Errorf("unable to open file %q: %v", p, err)
	}
	l := append([]byte{LeafHashPrefix}, f...)
	h := sha256.Sum256(l)
	copy(hash[:], h[:])

	return hash, nil
}
