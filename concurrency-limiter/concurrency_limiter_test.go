package limiter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func Test_Met_FalseWhenNoLimitSet(t *testing.T) {
	t.Parallel()

	clMet := false

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Millisecond * 10)
		w.WriteHeader(http.StatusAccepted)
	})

	limit := 0
	cl := NewConcurrencyLimiter(http.Handler(handler), limit)
	if cl.Met() == true {
		t.Fatalf("Want Met() to be false due to no requests, got: %t", cl.Met())
	}

	wg := &sync.WaitGroup{}
	wg.Add(3)
	go func() {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.ResponseRecorder{}
		cl.ServeHTTP(&rr, req)

		wg.Done()
	}()
	go func() {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.ResponseRecorder{}
		cl.ServeHTTP(&rr, req)

		wg.Done()
	}()

	// Is there a better way to catch the Met() function whilst at least
	// one of the HTTP calls is in progress?
	go func() {
		for i := 0; i < 100; i++ {
			if cl.Met() == true {
				clMet = true
				break
			}
			time.Sleep(time.Millisecond * 1)
		}
		wg.Done()
	}()

	wg.Wait()

	want := false
	if clMet != want {
		t.Fatalf("Want Met() to be false due to a limit of 0 request and 2 in-flight, got: %t", cl.Met())
	}
}

func Test_Met_True_When_OverLimit(t *testing.T) {
	t.Parallel()

	clMet := false

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Millisecond * 10)
		w.WriteHeader(http.StatusAccepted)
	})

	limit := 1
	cl := NewConcurrencyLimiter(http.Handler(handler), limit)
	if cl.Met() == true {
		t.Fatalf("Want Met() to be false due to no requests, got: %t", cl.Met())
	}

	wg := &sync.WaitGroup{}
	wg.Add(3)
	go func() {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.ResponseRecorder{}
		cl.ServeHTTP(&rr, req)

		wg.Done()
	}()
	go func() {
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.ResponseRecorder{}
		cl.ServeHTTP(&rr, req)

		wg.Done()
	}()

	// Is there a better way to catch the Met() function whilst at least
	// one of the HTTP calls is in progress?
	go func() {
		for i := 0; i < 100; i++ {
			if cl.Met() == true {
				clMet = true
				break
			}
			time.Sleep(time.Millisecond * 1)
		}
		wg.Done()
	}()

	wg.Wait()

	want := true
	if clMet != want {
		t.Fatalf("Want Met() to be true due to a limit of 1 request and 2 in-flight, got: %t", cl.Met())
	}
}

func makeFakeHandler(ctx context.Context, completeInFlightRequestChan chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-ctx.Done():
			w.WriteHeader(http.StatusServiceUnavailable)
		case <-completeInFlightRequestChan:
			w.WriteHeader(http.StatusOK)
		}
	}
}

func doRRandRequest(ctx context.Context, wg *sync.WaitGroup, cl http.Handler) *httptest.ResponseRecorder {
	// If wait for handler is true, it waits until the code is in the handler function
	rr := httptest.NewRecorder()
	// This should never fail unless we're out of memory or something
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		panic(err)
	}
	req = req.WithContext(ctx)

	wg.Add(1)
	go func() {
		// If this code path is meant to make it into the handler, we need a way to figure out if it's there or not
		cl.ServeHTTP(rr, req)
		// If the request was aborted, unblock any waiting goroutines
		wg.Done()
	}()

	return rr
}

func TestConcurrencyLimitUnderLimit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	completeInFlightRequestChan := make(chan struct{})
	handler := makeFakeHandler(ctx, completeInFlightRequestChan)
	cl := NewConcurrencyLimiter(http.Handler(handler), 2)

	wg := &sync.WaitGroup{}
	rr1 := doRRandRequest(ctx, wg, cl)
	// This will "release" the request rr1
	completeInFlightRequestChan <- struct{}{}

	// This should never take more than the timeout
	wg.Wait()

	// We want to access the response recorder directly, so we don't accidentally get an implicitly correct answer
	if rr1.Code != http.StatusOK {
		t.Fatalf("Want response code %d, got: %d", http.StatusOK, rr1.Code)
	}

}

func TestConcurrencyLimitAtLimit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	completeInFlightRequestChan := make(chan struct{})
	handler := makeFakeHandler(ctx, completeInFlightRequestChan)

	cl := NewConcurrencyLimiter(http.Handler(handler), 2)

	wg := &sync.WaitGroup{}
	rr1 := doRRandRequest(ctx, wg, cl)
	rr2 := doRRandRequest(ctx, wg, cl)

	completeInFlightRequestChan <- struct{}{}
	completeInFlightRequestChan <- struct{}{}

	wg.Wait()

	if rr1.Code != http.StatusOK {
		t.Fatalf("Want response code %d, got: %d", http.StatusOK, rr1.Code)
	}
	if rr2.Code != http.StatusOK {
		t.Fatalf("Want response code %d, got: %d", http.StatusOK, rr1.Code)
	}

}

func count(r *httptest.ResponseRecorder, code200s, code429s *int) {
	switch r.Code {
	case http.StatusTooManyRequests:
		*code429s = *code429s + 1
	case http.StatusOK:
		*code200s = *code200s + 1
	default:
		panic(fmt.Sprintf("Unknown code: %d", r.Code))
	}
}

func TestConcurrencyLimitOverLimit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	completeInFlightRequestChan := make(chan struct{}, 3)
	handler := makeFakeHandler(ctx, completeInFlightRequestChan)

	cl := NewConcurrencyLimiter(http.Handler(handler), 2)

	wg := &sync.WaitGroup{}

	rr1 := doRRandRequest(ctx, wg, cl)
	rr2 := doRRandRequest(ctx, wg, cl)
	for ctx.Err() == nil {
		if requestsStarted := atomic.LoadUint64(&cl.requestsStarted); requestsStarted == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	rr3 := doRRandRequest(ctx, wg, cl)
	for ctx.Err() == nil {
		if requestsStarted := atomic.LoadUint64(&cl.requestsStarted); requestsStarted == 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	completeInFlightRequestChan <- struct{}{}
	completeInFlightRequestChan <- struct{}{}
	completeInFlightRequestChan <- struct{}{}

	wg.Wait()

	code200s := 0
	code429s := 0
	count(rr1, &code200s, &code429s)
	count(rr2, &code200s, &code429s)
	count(rr3, &code200s, &code429s)
	if code200s != 2 || code429s != 1 {
		t.Fatalf("code 200s: %d, and code429s: %d", code200s, code429s)
	}

	want := "text/plain"
	gotContentType := 0
	gotInternalHeader := 0
	if rr1.Header().Get("Content-Type") == want {
		gotContentType++
	}
	if rr2.Header().Get("Content-Type") == want {
		gotContentType++
	}
	if rr3.Header().Get("Content-Type") == want {
		gotContentType++
	}

	if rr1.Header().Get("X-OpenFaaS-Internal") == "faas-middleware" {
		gotInternalHeader++
	}
	if rr2.Header().Get("X-OpenFaaS-Internal") == "faas-middleware" {
		gotInternalHeader++
	}
	if rr3.Header().Get("X-OpenFaaS-Internal") == "faas-middleware" {
		gotInternalHeader++
	}

	if gotContentType == 0 {
		t.Fatalf("Want at least one request with Content-Type %q, got: %q %q %q", want, rr1.Header().Get("Content-Type"), rr2.Header().Get("Content-Type"), rr3.Header().Get("Content-Type"))
	}

	if gotInternalHeader == 0 {
		t.Fatalf("Want at least one request with X-OpenFaaS-Internal header, got: %q %q %q", rr1.Header().Get("X-OpenFaaS-Internal"), rr2.Header().Get("X-OpenFaaS-Internal"), rr3.Header().Get("X-OpenFaaS-Internal"))
	}
}

func TestConcurrencyLimitOverLimitAndRecover(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	completeInFlightRequestChan := make(chan struct{}, 4)
	handler := makeFakeHandler(ctx, completeInFlightRequestChan)
	cl := NewConcurrencyLimiter(http.Handler(handler), 2)

	wg := &sync.WaitGroup{}

	rr1 := doRRandRequest(ctx, wg, cl)
	rr2 := doRRandRequest(ctx, wg, cl)
	for ctx.Err() == nil {
		if requestsStarted := atomic.LoadUint64(&cl.requestsStarted); requestsStarted == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// This will 429
	rr3 := doRRandRequest(ctx, wg, cl)
	for ctx.Err() == nil {
		if requestsStarted := atomic.LoadUint64(&cl.requestsStarted); requestsStarted == 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	completeInFlightRequestChan <- struct{}{}
	completeInFlightRequestChan <- struct{}{}
	completeInFlightRequestChan <- struct{}{}
	// Although we could do another wg.Wait here, I don't think we should because
	// it might provide a false sense of confidence
	for ctx.Err() == nil {
		if requestsCompleted := atomic.LoadUint64(&cl.requestsCompleted); requestsCompleted == 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	rr4 := doRRandRequest(ctx, wg, cl)
	completeInFlightRequestChan <- struct{}{}
	wg.Wait()

	code200s := 0
	code429s := 0
	count(rr1, &code200s, &code429s)
	count(rr2, &code200s, &code429s)
	count(rr3, &code200s, &code429s)
	count(rr4, &code200s, &code429s)

	if code200s != 3 || code429s != 1 {
		t.Fatalf("code 200s: %d, and code429s: %d", code200s, code429s)
	}
}
