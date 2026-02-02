// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_debug

package wgengine

import (
	"fmt"
	"log"
	"net/netip"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgint"
)

// NewWatchdog wraps an Engine and makes sure that all methods complete
// within a reasonable amount of time.  The usermetric.Registry argument
// may be nil; if non-nil, watchdog timeout metrics are registered there.
//
// If they do not, the watchdog crashes the process.
func NewWatchdog(e Engine, mr *usermetric.Registry) Engine {
	if envknob.Bool("TS_DEBUG_DISABLE_WATCHDOG") {
		return e
	}

	we := &watchdogEngine{
		wrap:     e,
		logf:     log.Printf,
		fatalf:   log.Fatalf,
		maxWait:  45 * time.Second,
		inFlight: make(map[inFlightKey]time.Time),
	}
	if mr != nil {
		we.registerMetrics(mr)
	}
	return we
}

type inFlightKey struct {
	op  watchdogEvent
	ctr uint64
}

type watchdogEngine struct {
	wrap    Engine
	logf    func(format string, args ...any)
	fatalf  func(format string, args ...any)
	maxWait time.Duration
	metrics *usermetric.MultiLabelMap[eventLabel]

	// Track the start time(s) of in-flight operations
	inFlightMu  sync.Mutex
	inFlight    map[inFlightKey]time.Time
	inFlightCtr uint64
}

type watchdogEvent string

var (
	Any               watchdogEvent = "Any"
	Reconfig          watchdogEvent = "Reconfig"
	ResetAndStop      watchdogEvent = "ResetAndStop"
	SetFilter         watchdogEvent = "SetFilter"
	SetJailedFilter   watchdogEvent = "SetJailedFilter"
	SetStatusCallback watchdogEvent = "SetStatusCallback"
	UpdateStatus      watchdogEvent = "UpdateStatus"
	RequestStatus     watchdogEvent = "RequestStatus"
	SetNetworkMap     watchdogEvent = "SetNetworkMap"
	Ping              watchdogEvent = "Ping"
	Close             watchdogEvent = "Close"
	PeerForIPEvent    watchdogEvent = "PeerForIP"
)

type eventLabel struct {
	Type watchdogEvent
}

// registerMetrics sets up the watchdog timeout metrics.  We register a separate
// gauge for each watchdogEvent type.
func (e *watchdogEngine) registerMetrics(reg *usermetric.Registry) {
	m := usermetric.NewMultiLabelMapWithRegistry[eventLabel](
		reg,
		"watchdog_timeout",
		"counter",
		"Number of watchdog timeouts by operation type.",
	)
	m.Set(eventLabel{Type: Any}, reg.NewGauge("watchdog_timeout_any", "Total number of watchdog timeouts"))
	m.Set(eventLabel{Type: Reconfig}, reg.NewGauge("watchdog_timeout_reconfig", "Number of watchdog timeouts for Reconfig operation"))
	m.Set(eventLabel{Type: ResetAndStop}, reg.NewGauge("watchdog_timeout_resetandstop", "Number of watchdog timeouts for ResetAndStop operation"))
	m.Set(eventLabel{Type: SetFilter}, reg.NewGauge("watchdog_timeout_setfilter", "Number of watchdog timeouts for SetFilter operation"))
	m.Set(eventLabel{Type: SetJailedFilter}, reg.NewGauge("watchdog_timeout_setjailedfilter", "Number of watchdog timeouts for SetJailedFilter operation"))
	m.Set(eventLabel{Type: SetStatusCallback}, reg.NewGauge("watchdog_timeout_setstatuscallback", "Number of watchdog timeouts for SetStatusCallback operation"))
	m.Set(eventLabel{Type: UpdateStatus}, reg.NewGauge("watchdog_timeout_updatestatus", "Number of watchdog timeouts for UpdateStatus operation"))
	m.Set(eventLabel{Type: RequestStatus}, reg.NewGauge("watchdog_timeout_requeststatus", "Number of watchdog timeouts for RequestStatus operation"))
	m.Set(eventLabel{Type: SetNetworkMap}, reg.NewGauge("watchdog_timeout_setnetworkmap", "Number of watchdog timeouts for SetNetworkMap operation"))
	m.Set(eventLabel{Type: Ping}, reg.NewGauge("watchdog_timeout_ping", "Number of watchdog timeouts for Ping operation"))
	m.Set(eventLabel{Type: Close}, reg.NewGauge("watchdog_timeout_close", "Number of watchdog timeouts for Close operation"))
	m.Set(eventLabel{Type: PeerForIPEvent}, reg.NewGauge("watchdog_timeout_peerforipevent", "Number of watchdog timeouts for PeerForIPEvent operation"))
	e.metrics = m
}

func (e *watchdogEngine) watchdogErr(event watchdogEvent, fn func() error) error {
	// Track all in-flight operations so we can print more useful error
	// messages on watchdog failure
	e.inFlightMu.Lock()

	key := inFlightKey{
		op:  event,
		ctr: e.inFlightCtr,
	}
	e.inFlightCtr++
	e.inFlight[key] = time.Now()
	e.inFlightMu.Unlock()

	defer func() {
		e.inFlightMu.Lock()
		defer e.inFlightMu.Unlock()
		delete(e.inFlight, key)
	}()

	errCh := make(chan error)
	go func() {
		errCh <- fn()
	}()
	t := time.NewTimer(e.maxWait)
	select {
	case err := <-errCh:
		t.Stop()
		return err
	case <-t.C:
		buf := new(strings.Builder)
		pprof.Lookup("goroutine").WriteTo(buf, 1)
		e.logf("wgengine watchdog stacks:\n%s", buf.String())
		// Collect the list of in-flight operations for debugging.
		var (
			b   []byte
			now = time.Now()
		)
		e.inFlightMu.Lock()
		for k, t := range e.inFlight {
			dur := now.Sub(t).Round(time.Millisecond)
			b = fmt.Appendf(b, "in-flight[%d]: name=%s duration=%v start=%s\n", k.ctr, k.op, dur, t.Format(time.RFC3339Nano))
		}
		e.recordEvent(event)
		e.inFlightMu.Unlock()

		// Print everything as a single string to avoid log
		// rate limits.
		e.logf("wgengine watchdog in-flight:\n%s", b)
		e.fatalf("wgengine: watchdog timeout on %s", event)
		return nil
	}
}

func (e *watchdogEngine) recordEvent(event watchdogEvent) {
	if e.metrics == nil {
		return
	}

	mEvent, ok := e.metrics.Get(eventLabel{Type: event}).(*usermetric.Gauge)
	if ok {
		mEvent.Add(1)
	}
	mAny, ok := e.metrics.Get(eventLabel{Type: Any}).(*usermetric.Gauge)
	if ok {
		mAny.Add(1)
	}
}

func (e *watchdogEngine) watchdog(event watchdogEvent, fn func()) {
	e.watchdogErr(event, func() error {
		fn()
		return nil
	})
}

func (e *watchdogEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config, dnsCfg *dns.Config) error {
	return e.watchdogErr(Reconfig, func() error { return e.wrap.Reconfig(cfg, routerCfg, dnsCfg) })
}

func (e *watchdogEngine) ResetAndStop() (st *Status, err error) {
	e.watchdog(ResetAndStop, func() {
		st, err = e.wrap.ResetAndStop()
	})
	return st, err
}

func (e *watchdogEngine) GetFilter() *filter.Filter {
	return e.wrap.GetFilter()
}

func (e *watchdogEngine) SetFilter(filt *filter.Filter) {
	e.watchdog(SetFilter, func() { e.wrap.SetFilter(filt) })
}

func (e *watchdogEngine) GetJailedFilter() *filter.Filter {
	return e.wrap.GetJailedFilter()
}

func (e *watchdogEngine) SetJailedFilter(filt *filter.Filter) {
	e.watchdog(SetJailedFilter, func() { e.wrap.SetJailedFilter(filt) })
}

func (e *watchdogEngine) SetStatusCallback(cb StatusCallback) {
	e.watchdog(SetStatusCallback, func() { e.wrap.SetStatusCallback(cb) })
}

func (e *watchdogEngine) UpdateStatus(sb *ipnstate.StatusBuilder) {
	e.watchdog(UpdateStatus, func() { e.wrap.UpdateStatus(sb) })
}

func (e *watchdogEngine) RequestStatus() {
	e.watchdog(RequestStatus, func() { e.wrap.RequestStatus() })
}

func (e *watchdogEngine) SetNetworkMap(nm *netmap.NetworkMap) {
	e.watchdog(SetNetworkMap, func() { e.wrap.SetNetworkMap(nm) })
}

func (e *watchdogEngine) Ping(ip netip.Addr, pingType tailcfg.PingType, size int, cb func(*ipnstate.PingResult)) {
	e.watchdog(Ping, func() { e.wrap.Ping(ip, pingType, size, cb) })
}

func (e *watchdogEngine) Close() {
	e.watchdog(Close, e.wrap.Close)
}

func (e *watchdogEngine) PeerForIP(ip netip.Addr) (ret PeerForIP, ok bool) {
	e.watchdog(PeerForIPEvent, func() { ret, ok = e.wrap.PeerForIP(ip) })
	return ret, ok
}

func (e *watchdogEngine) Done() <-chan struct{} {
	return e.wrap.Done()
}

func (e *watchdogEngine) InstallCaptureHook(cb packet.CaptureCallback) {
	if !buildfeatures.HasCapture {
		return
	}
	e.wrap.InstallCaptureHook(cb)
}

func (e *watchdogEngine) PeerByKey(pubKey key.NodePublic) (_ wgint.Peer, ok bool) {
	return e.wrap.PeerByKey(pubKey)
}
