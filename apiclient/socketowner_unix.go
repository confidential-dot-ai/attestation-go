//go:build unix

package apiclient

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkSocketOwner requires the socket to be owned by root or by this process.
// Any other owner can replace it, and the client cannot tell a substituted
// service from the real one once connected.
func checkSocketOwner(fi fs.FileInfo, socketPath string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("attestation-api socket %q: ownership cannot be read from %T", socketPath, fi.Sys())
	}
	if st.Uid != 0 && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("attestation-api socket %q is owned by uid %d (want root or this process's uid)", socketPath, st.Uid)
	}
	return nil
}
