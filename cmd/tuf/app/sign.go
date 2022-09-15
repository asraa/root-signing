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

//go:build pivkey
// +build pivkey

package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/sigstore/cosign/pkg/cosign/pivkey"
	csignature "github.com/sigstore/cosign/pkg/signature"
	pkeys "github.com/sigstore/root-signing/pkg/keys"
	"github.com/sigstore/root-signing/pkg/repo"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	cjson "github.com/tent/canonical-json-go"
	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
)

type roleFlag []string

func (f *roleFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *roleFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type FormatType int

const (
	Hex FormatType = iota
	Pem
	HexAndPem
)

func Sign() *ffcli.Command {
	var (
		flagset    = flag.NewFlagSet("tuf sign", flag.ExitOnError)
		roles      = roleFlag{}
		repository = flagset.String("repository", "", "path to the staged repository")
		sk         = flagset.Bool("sk", false, "indicates use of a hardware key for signing")
		key        = flagset.String("key", "", "reference to an onine signer for signing")
	)
	flagset.Var(&roles, "roles", "role(s) to sign")
	return &ffcli.Command{
		Name:       "sign",
		ShortUsage: "tuf signs the top-level metadata for role in the given repository",
		ShortHelp:  "tuf signs the top-level metadata for role in the given repository",
		LongHelp: `tuf signs the top-level metadata for role in the given repository.
		Signing a lower level, e.g. snapshot or timestamp, before signing the root and target
		will trigger a warning. 
		One of sk or a key reference must be provided.
		
	EXAMPLES
	# sign staged repository at ceremony/YYYY-MM-DD
	tuf sign -role root -repository ceremony/YYYY-MM-DD`,
		FlagSet: flagset,
		Exec: func(ctx context.Context, args []string) error {
			if *repository == "" || len(roles) == 0 {
				return flag.ErrHelp
			}
			if !*sk && *key == "" {
				return flag.ErrHelp
			}
			signer, err := getSigner(ctx, *sk, *key)
			if err != nil {
				return err
			}
			var format = Pem
			if DeprecatedEcdsaFormat {
				format = Hex
				for _, role := range roles {
					if role == "root" && sk != nil && *sk {
						// For v5 only! Get both formats when using an sk for root role.
						format = HexAndPem
					}
				}
			}
			return SignCmd(ctx, *repository, roles, signer, format)
		},
	}
}

func checkMetaForRole(store tuf.LocalStore, role []string) error {
	db, _, err := repo.CreateDb(store)
	if err != nil {
		return fmt.Errorf("error creating verification database: %w", err)
	}
	for _, role := range role {
		switch role {
		case "snapshot":
			// Check that root and target are signed correctly
			for _, manifest := range []string{"root", "targets"} {
				s, err := repo.GetSignedMeta(store, manifest+".json")
				if err != nil {
					return err
				}

				if err := db.Verify(s, manifest, 0); err != nil {
					return fmt.Errorf("error verifying signatures for %s: %w", manifest, err)
				}
			}
		case "timestamp":
			// Check that snapshot is signed
			s, err := repo.GetSignedMeta(store, "snapshot.json")
			if err != nil {
				return err
			}
			if err := db.Verify(s, "snapshot", 0); err != nil {
				return fmt.Errorf("error verifying signatures for snapshot: %w", err)
			}
		case "default":
			// No pre-requisites for signing root and target
			continue
		}
	}
	return nil
}

func getSigner(ctx context.Context, sk bool, keyRef string) (signature.SignerVerifier, error) {
	if sk {
		pivKey, err := pivkey.GetKeyWithSlot("signature")
		if err != nil {
			return nil, err
		}
		return pivKey.SignerVerifier()
	}
	// A key reference was provided.
	return csignature.SignerVerifierFromKeyRef(ctx, keyRef, nil)
}

func SignCmd(ctx context.Context, directory string, roles []string, signer signature.SignerVerifier,
	format FormatType) error {
	store := tuf.FileSystemStore(directory, nil)

	if err := checkMetaForRole(store, roles); err != nil {
		return fmt.Errorf("signing pre-requisites failed: %w", err)
	}

	for _, name := range roles {
		if err := SignMeta(ctx, store, name+".json", signer, format); err != nil {
			return err
		}
	}

	return nil
}

func SignMeta(ctx context.Context, store tuf.LocalStore, name string, signer signature.SignerVerifier,
	format FormatType) error {
	fmt.Printf("Signing metadata for %s... \n", name)
	s, err := repo.GetSignedMeta(store, name)
	if err != nil {
		return err
	}
	if (name == "root.json" || name == "targets.json") && s.Signatures == nil {
		// init-repo should have pre-populated these. don't lose them.
		return errors.New("pre-entries not defined")
	}

	// Sign payload
	meta, err := repo.GetMetaFromStore(s.Signed, name)
	if err != nil {
		return err
	}
	msg, err := cjson.Marshal(meta)
	if err != nil {
		return err
	}

	sig, err := signer.SignMessage(bytes.NewReader(msg), options.WithContext(ctx))
	if err != nil {
		return err
	}

	sigs := make([]data.Signature, 0, len(s.Signatures))

	// Get all possible TUF key IDs.
	ids, err := getTufKeyIDs(ctx, signer)
	if err != nil {
		return err
	}

	// Add it to your key entry
	var added bool
	for _, id := range ids {
		// If pre-entries are defined.
		if arePreEntriesDefined(s) {
			for _, entry := range s.Signatures {
				if entry.KeyID == id {
					sigs = append(sigs, data.Signature{
						KeyID:     id,
						Signature: sig,
					})
					added = true
				} else {
					sigs = append(sigs, entry)
				}
			}
		} else {
			sigs = append(sigs, data.Signature{
				KeyID:     id,
				Signature: sig,
			})
			added = true
		}
	}

	if !added {
		return fmt.Errorf("expected key ID %s for metadata role %s", strings.Join(ids, ", "), name)
	}

	return setSignedMeta(store, name, &data.Signed{Signatures: sigs, Signed: s.Signed})
}

// Pre-entries are defined when there are Signatures in the Signed metadata
// in which Key IDs are defined with empty signatures.
// TODO(asraa): Add unit testing for pre-entries.
func arePreEntriesDefined(s *data.Signed) bool {
	if s.Signatures != nil {
		for _, entry := range s.Signatures {
			if len(entry.KeyID) != 0 && len(entry.Signature) == 0 {
				return true
			}
		}
	}
	return false
}

func getTufKeyIDs(ctx context.Context, verifier signature.Verifier) ([]string, error) {
	var ids []string
	key, err := pkeys.ConstructTufKey(ctx, verifier, true)
	if err != nil {
		return nil, err
	}
	ids = append(ids, key.IDs()...)
	key, err = pkeys.ConstructTufKey(ctx, verifier, false)
	if err != nil {
		return nil, err
	}
	ids = append(ids, key.IDs()...)
	return ids, nil
}
