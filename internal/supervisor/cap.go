package supervisor

import (
	"fmt"
	"io"
)

// protectedOutputCap bounds how much one protected job may write to each of
// its captured streams (the out file and the err file). The worker's stdout
// and stderr both land on the control plane's disk, and the worker's view of
// the world is untrusted, so a stuck or malicious worker must not be able to
// fill that disk through them. 64 MiB per stream is far above any legitimate
// answer and far below a disk-filling flood. Non-protected jobs keep the
// upstream uncaptured behavior: the cap keys on the ownership record, like the
// strict environment does.
const protectedOutputCap = 64 << 20

// truncationNotice is written once when a capped writer first exceeds its cap,
// so a reader of the file can tell truncation apart from a short answer.
const truncationNotice = "\n[agy-mcp: output capped at 64 MiB for this protected job; further output was discarded]\n"

// cappedWriter writes at most remaining bytes to w, then discards the rest.
// After the cap it reports the full input as written (the probeOutput
// precedent): the producers here are os/exec's stderr copy and the supervisor's
// stream drain, and a short write or error would surface as a Wait failure that
// blames the run instead of the cap. The cap is a disk bound, not a backpressure
// signal; a worker that writes this much is stuck or flooding and the notice
// in the file is what tells the operator so.
type cappedWriter struct {
	w         io.Writer
	remaining int64
	notified  bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.remaining <= 0 {
		c.note()
		return len(p), nil
	}
	if int64(len(p)) <= c.remaining {
		n, err := c.w.Write(p)
		c.remaining -= int64(n)
		return n, err
	}
	n, err := c.w.Write(p[:c.remaining])
	c.remaining -= int64(n)
	c.note()
	// Claim the whole input consumed, for the same reason as above.
	return len(p), err
}

func (c *cappedWriter) note() {
	if c.notified {
		return
	}
	c.notified = true
	// A failed notice write means the disk is already full; nothing more can
	// be done here and the sentinel still gets written, so ignore the error.
	_, _ = fmt.Fprint(c.w, truncationNotice)
}
