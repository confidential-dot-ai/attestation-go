package remote

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
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
