// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"runtime"
	"testing"
	"time"

	"tailscale.com/health"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
)

func TestWatchdog(t *testing.T) {
	t.Parallel()

	var maxWaitMultiple time.Duration = 1
	if runtime.GOOS == "darwin" {
		// Work around slow close syscalls on Big Sur with content filter Network Extensions installed.
		// See https://github.com/tailscale/tailscale/issues/1598.
		maxWaitMultiple = 15
	}

	t.Run("default watchdog does not fire", func(t *testing.T) {
		t.Parallel()
		bus := eventbustest.NewBus(t)
		ht := health.NewTracker(bus)
		reg := new(usermetric.Registry)
		e, err := NewFakeUserspaceEngine(t.Logf, 0, ht, reg, bus)
		if err != nil {
			t.Fatal(err)
		}
		mr := new(usermetric.Registry)

		e = NewWatchdog(e, mr)
		e.(*watchdogEngine).maxWait = maxWaitMultiple * 150 * time.Millisecond
		e.(*watchdogEngine).logf = t.Logf
		e.(*watchdogEngine).fatalf = t.Fatalf

		e.RequestStatus()
		e.RequestStatus()
		e.RequestStatus()
		e.Close()
	})
}

func TestWatchdogMetrics(t *testing.T) {
	logf := func(format string, args ...any) {}
	bus := eventbustest.NewBus(t)
	ht := health.NewTracker(bus)
	reg := new(usermetric.Registry)
	e, err := NewFakeUserspaceEngine(logf, 0, ht, reg, bus)
	if err != nil {
		t.Fatal(err)
	}
	e = NewWatchdog(e, reg)
	w := e.(*watchdogEngine)
	// 0 is not valid
	w.maxWait = 1 * time.Microsecond
	// Swallow the stack trace logs and fatal logs.
	w.logf = logf
	w.fatalf = logf

	timer := time.NewTimer(1 * time.Millisecond)
	done := make(chan struct{})
	w.watchdog(RequestStatus, func() {
		<-timer.C
		close(done)
	})
	w.watchdog(PeerForIPEvent, func() {
		<-timer.C
		close(done)
	})
	<-done

	// One RequestStatus event
	m := w.metrics.Get(eventLabel{Type: RequestStatus})
	got := m.(*usermetric.Gauge).Value()
	if got < 0.99 {
		t.Fatalf("got %f metric events for RequestStatus, want %v", got, 1)
	}

	// 2 events total
	m = w.metrics.Get(eventLabel{Type: Any})
	got = m.(*usermetric.Gauge).Value()
	if got < 1.99 {
		t.Fatalf("got %f metric events for RequestStatus, want %v", got, 2)
	}
}
