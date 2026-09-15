package remote

import (
	"context"
	"fmt"
	"time"
)

// WaitHealthy waits until the API reports healthy. The caller's context bounds
// the total wait; interval bounds each Health request and the pause after a
// failed attempt. Cancellation interrupts both the request and the pause.
func (c Client) WaitHealthy(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("health interval must be positive")
	}
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait for healthy attestation-api: %w (last health check: %v)", err, lastErr)
		}
		attemptCtx, cancel := context.WithTimeout(ctx, interval)
		health, err := c.Health(attemptCtx)
		cancel()
		if err == nil && health.Status == "ok" {
			return ctx.Err()
		}
		if err == nil {
			err = fmt.Errorf("health status %q, want ok", health.Status)
		}
		lastErr = err
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for healthy attestation-api: %w (last health check: %v)", ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}
