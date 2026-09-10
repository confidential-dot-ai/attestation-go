//go:build !unix

package client

import (
	"fmt"
	"io/fs"
)

// checkSocketOwner refuses socket addresses where ownership cannot be checked.
// Failing closed beats dialing a socket whose owner is unknown.
func checkSocketOwner(_ fs.FileInfo, socketPath string) error {
	return fmt.Errorf("attestation-api socket %q: ownership cannot be checked on this platform", socketPath)
}
