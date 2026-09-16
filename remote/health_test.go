package remote

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestWaitHealthyRetriesUntilReady(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" || r.Method != http.MethodGet {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		switch attempts.Add(1) {
		case 1:
			http.Error(w, "starting", http.StatusServiceUnavailable)
		case 2:
			_, _ = w.Write([]byte(`{"status":"starting"}`))
		default:
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := NewClient(srv.URL).WaitHealthy(ctx, 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestWaitHealthyBoundsRequestsAndTotalWait(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := NewClient(srv.URL).WaitHealthy(ctx, 10*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want caller deadline", err)
	}
	if time.Since(start) > time.Second {
		t.Error("caller deadline did not interrupt health wait")
	}
	if attempts.Load() < 2 {
		t.Error("a hung health request prevented retries")
	}
}

func TestWaitHealthyPausesAfterFailedRequest(t *testing.T) {
	const interval = time.Second
	for _, duration := range []time.Duration{interval / 2, interval} {
		t.Run(duration.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				start := time.Now()
				var attempts []time.Duration
				client := NewClientWithHTTP("http://health.test", &http.Client{
					Transport: healthRoundTripperFunc(func(*http.Request) (*http.Response, error) {
						attempts = append(attempts, time.Since(start))
						if len(attempts) == 1 {
							time.Sleep(duration)
						} else {
							cancel()
						}
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{"status":"starting"}`)),
						}, nil
					}),
				})
				err := client.WaitHealthy(ctx, interval)
				if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), `health status "starting"`) {
					t.Fatalf("error = %v, want cancellation with last unhealthy status", err)
				}
				if len(attempts) != 2 {
					t.Fatalf("attempts = %v, want two requests", attempts)
				}
				if attempts[0] != 0 || attempts[1] != duration+interval {
					t.Errorf("request times = %v, want [0 %s]", attempts, duration+interval)
				}
			})
		})
	}
}

type healthRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f healthRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestWaitHealthyCancelsPauseAndRejectsInvalidInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		close(called)
	}))
	defer srv.Close()
	client := NewClient(srv.URL)
	done := make(chan error, 1)
	go func() { done <- client.WaitHealthy(ctx, time.Hour) }()
	<-called
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt wait")
	}
	if err := client.WaitHealthy(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Errorf("already canceled context = %v", err)
	}
	for _, interval := range []time.Duration{0, -time.Second} {
		if err := client.WaitHealthy(context.Background(), interval); err == nil {
			t.Errorf("accepted interval %s", interval)
		}
	}
}
