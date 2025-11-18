//
// Copyright 2021 The Sigstore Authors.
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

package cosign

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// SimpleClaimVerifier verifies that sig.Payload() is a SimpleContainerImage payload which references the given image digest and contains the given annotations.
func SimpleClaimVerifier(sig oci.Signature, imageDigest v1.Hash, annotations map[string]interface{}) error {
	p, err := sig.Payload()
	if err != nil {
		return err
	}

	ss := &payload.SimpleContainerImage{}
	if err := json.Unmarshal(p, ss); err != nil {
		return err
	}

	foundDgst := ss.Critical.Image.DockerManifestDigest
	if foundDgst != imageDigest.String() {
		return fmt.Errorf("invalid or missing digest in claim: %s", foundDgst)
	}

	if annotations != nil {
		if !correctAnnotations(annotations, ss.Optional) {
			return errors.New("missing or incorrect annotation")
		}
	}

	return nil
}

// IntotoSubjectClaimVerifier verifies that sig.Payload() is an Intoto statement which references the given image digest.
func IntotoSubjectClaimVerifier(sig oci.Signature, imageDigest v1.Hash, annotations map[string]interface{}) error {
	claimStart := time.Now()
	fmt.Fprintf(os.Stderr, "[TIMING]         >> IntotoSubjectClaimVerifier started\n")

	payloadStart := time.Now()
	p, err := sig.Payload()
	fmt.Fprintf(os.Stderr, "[TIMING]         sig.Payload() in ClaimVerifier took %v\n", time.Since(payloadStart))
	if err != nil {
		return err
	}

	// The payload here is an envelope. We already verified the signature earlier.
	unmarshal1Start := time.Now()
	e := dsse.Envelope{}
	if err := json.Unmarshal(p, &e); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[TIMING]         Unmarshal envelope took %v\n", time.Since(unmarshal1Start))

	decodeStart := time.Now()
	stBytes, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[TIMING]         Base64 decode took %v\n", time.Since(decodeStart))

	unmarshal2Start := time.Now()
	st := in_toto.Statement{}
	if err := json.Unmarshal(stBytes, &st); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[TIMING]         Unmarshal in-toto statement took %v (statement size: %d bytes)\n", time.Since(unmarshal2Start), len(stBytes))

	loopStart := time.Now()
	for _, subj := range st.Subject {
		dgst, ok := subj.Digest["sha256"]
		if !ok {
			continue
		}
		subjDigest := "sha256:" + dgst
		if subjDigest != imageDigest.String() {
			continue
		}
		annotStart := time.Now()
		if !correctAnnotations(annotations, subj.Annotations.AsMap()) {
			return errors.New("missing or incorrect annotation")
		}
		fmt.Fprintf(os.Stderr, "[TIMING]         correctAnnotations took %v\n", time.Since(annotStart))
		fmt.Fprintf(os.Stderr, "[TIMING]         Total IntotoSubjectClaimVerifier took %v\n", time.Since(claimStart))
		return nil
	}
	fmt.Fprintf(os.Stderr, "[TIMING]         Subject loop took %v (checked %d subjects)\n", time.Since(loopStart), len(st.Subject))
	return errors.New("no matching subject digest found")
}
