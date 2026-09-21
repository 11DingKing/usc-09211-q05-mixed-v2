// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// LLGR multipath regression suite.
//
// The live-cutover incident: when a prefix had both a fresh path and an
// LLGR_STALE path, getMultiBestPath assembled an ECMP group over both and
// the FIB kept forwarding traffic to the dead campus egress. These tests
// drive the full server propagation chain (global RIB multipath
// calculation, best-path watcher events that feed the FIB, downstream peer
// advertisements and ADD-PATH bookkeeping) to lock the required behavior:
//
//   - a fresh path must never be equivalent to an LLGR_STALE path;
//   - an all-stale destination keeps the RFC 9494 degraded semantics;
//   - out-of-order withdraws, policy recomputation and simultaneous
//     convergence of several peers converge to the same result;
//   - the timer transition and ADD-PATH produce no spurious withdraws;
//   - families/neighbors without LLGR keep their pre-existing behavior.

const llgrMultipathPrefixV4 = "192.0.2.0/24"
const llgrMultipathPrefixV6 = "2001:db8::/64"

// llgrTestServer builds a multipath-enabled server with two synthetic
// source peers and two downstream peers, all registered in neighborMap so
// that propagateUpdate fans out exactly like the live FSM path.
type llgrTestHarness struct {
	t       *testing.T
	s       *BgpServer
	sources map[string]*peer
	dwn     map[string]*peer
	mu      sync.Mutex
	events  []*watchEventBestPath
}

func ocLongLived(enabled bool) oc.LongLivedGracefulRestart {
	return oc.LongLivedGracefulRestart{
		Config: oc.LongLivedGracefulRestartConfig{Enabled: enabled},
		State:  oc.LongLivedGracefulRestartState{Enabled: enabled},
	}
}

func newLLGRTestHarness(t *testing.T) *llgrTestHarness {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:              65001,
			RouterId:         "10.255.255.1",
			ListenPort:       -1,
			UseMultiplePaths: true,
		},
	}))
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	h := &llgrTestHarness{
		t:       t,
		s:       s,
		sources: map[string]*peer{},
		dwn:     map[string]*peer{},
	}

	// Drain best-path events into a slice; the assertions below inspect
	// every event the FIB watcher (zclient/BMP) would have observed.
	w, err := s.watch(WatchBestPath(false))
	require.NoError(t, err)
	t.Cleanup(w.Stop)
	go func() {
		for ev := range w.Event() {
			if b, ok := ev.(*watchEventBestPath); ok {
				h.mu.Lock()
				h.events = append(h.events, b)
				h.mu.Unlock()
			}
		}
	}()

	return h
}

// addSourcePeer creates an eBGP source peer. llgr enables the Long-Lived
// GR capability for IPv4 unicast, matching the configuration that makes
// postFilterpath keep LLGR_STALE routes when propagating onward.
func (h *llgrTestHarness) addSourcePeer(name, addr string, asn uint32) *peer {
	h.t.Helper()
	p := newPeerandInfo(h.t, 65001, asn, addr, h.s.globalRib)
	p.policy = h.s.policy
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE,
		bgp.RF_IPv6_UC: bgp.BGP_ADD_PATH_NONE,
	})
	// The synthetic default config only enables IPv4 unicast, but the
	// non-LLGR-family test exercises an IPv6 reset: build the Adj-RIB-In
	// with both families as an IPv6-capable real session would have.
	p.adjRibIn = table.NewAdjRib(logger, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC})
	h.register(addr, p)
	h.sources[name] = p
	return p
}

// addDownstreamPeer creates an eBGP downstream peer. llgr controls whether
// the Long-Lived GR capability is enabled (IPv4 unicast), mirroring the
// campus routers that must or must not receive LLGR_STALE routes.
func (h *llgrTestHarness) addDownstreamPeer(name, addr string, asn uint32, llgr bool, addPathSendMax uint8) *peer {
	h.t.Helper()
	p := newPeerandInfo(h.t, 65001, asn, addr, h.s.globalRib)
	p.policy = h.s.policy
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)

	mode := bgp.BGP_ADD_PATH_NONE
	if addPathSendMax > 0 {
		mode = bgp.BGP_ADD_PATH_SEND
	}
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: mode,
		bgp.RF_IPv6_UC: mode,
	})

	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.GracefulRestart.Config.LongLivedEnabled = llgr
	for i := range conf.AfiSafis {
		family := conf.AfiSafis[i].State.Family
		if family != bgp.RF_IPv4_UC {
			continue
		}
		if llgr {
			conf.AfiSafis[i].LongLivedGracefulRestart = ocLongLived(true)
		}
		if addPathSendMax > 0 {
			conf.AfiSafis[i].AddPaths.Config.SendMax = addPathSendMax
			conf.AfiSafis[i].AddPaths.State.SendMax = addPathSendMax
		}
	}
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()

	h.register(addr, p)
	h.dwn[name] = p
	return p
}

func (h *llgrTestHarness) register(addr string, p *peer) {
	h.t.Helper()
	a := netip.MustParseAddr(addr)
	require.NoError(h.t, h.s.mgmtOperation(func() error {
		h.s.neighborMap[a] = p
		return nil
	}, true))
	h.t.Cleanup(func() {
		_ = h.s.mgmtOperation(func() error {
			delete(h.s.neighborMap, a)
			return nil
		}, false)
		cleanInfiniteChannel(p.fsm.outgoingCh)
	})
}

// learnPath builds an eBGP-learned path whose Compare()-relevant attributes
// (local-pref/AS_PATH length/origin/MED) are identical across source peers,
// which is exactly the condition under which the stale path used to slip
// into multipath.
func learnPath(t *testing.T, p *peer, prefix, nexthop string, stale bool) *table.Path {
	t.Helper()
	pfx, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	asPath := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{p.AS()}),
	})
	var attrs []bgp.PathAttributeInterface
	if pfx.Prefix.Addr().Is4() {
		nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
		require.NoError(t, err)
		attrs = []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), asPath, nh}
	} else {
		mpReach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC,
			[]bgp.PathNLRI{{NLRI: pfx}}, netip.MustParseAddr(nexthop))
		require.NoError(t, err)
		attrs = []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), asPath, mpReach}
	}
	path := table.NewPath(pfxFamily(prefix), p.peerInfo.Load(),
		bgp.PathNLRI{NLRI: pfx}, false, attrs, time.Now(), false)
	if stale {
		path.SetCommunities([]uint32{uint32(bgp.COMMUNITY_LLGR_STALE)}, false)
	}
	return path
}

func pfxFamily(prefix string) bgp.Family {
	if netip.MustParsePrefix(prefix).Addr().Is4() {
		return bgp.RF_IPv4_UC
	}
	return bgp.RF_IPv6_UC
}

// ingest feeds a learned path through both the source peer Adj-RIB-In and
// the global propagation chain, as handleUpdate does.
func (h *llgrTestHarness) ingest(p *peer, path *table.Path) {
	h.t.Helper()
	p.adjRibIn.Update([]*table.Path{path})
	h.s.propagateUpdate(p, []*table.Path{path})
}

// enterLLGR marks the source peer's IPv4 routes LLGR_STALE (session reset
// with LLGR) and propagates the marked paths, mirroring the IDLE branch in
// handleFSMMessage.
func (h *llgrTestHarness) enterLLGR(p *peer) {
	h.t.Helper()
	marked := p.markLLGRStale([]bgp.Family{bgp.RF_IPv4_UC})
	h.s.propagateUpdate(p, marked)
}

// multipathNextHops returns the global-RIB multipath next hops for the
// prefix, in best-path order.
func (h *llgrTestHarness) multipathNextHops(prefix string) []string {
	h.t.Helper()
	groups := h.s.globalRib.GetBestMultiPathList(table.GLOBAL_RIB_NAME,
		[]bgp.Family{pfxFamily(prefix)})
	var nhs []string
	for _, group := range groups {
		for _, p := range group {
			if p.GetPrefix() == prefix {
				nhs = append(nhs, p.GetNexthop().String())
			}
		}
	}
	return nhs
}

// drainOutgoing collects every UPDATE currently queued for a downstream
// peer (first message waits up to a second; subsequent messages are
// coalesced with a short quiet period).
func (h *llgrTestHarness) drainOutgoing(p *peer) []*table.Path {
	h.t.Helper()
	var paths []*table.Path
	deadline := time.After(time.Second)
	for {
		quiet := 50 * time.Millisecond
		if len(paths) == 0 {
			quiet = time.Second
		}
		select {
		case o := <-p.fsm.outgoingCh.Out():
			msg, ok := o.(*fsmOutgoingMsg)
			require.True(h.t, ok)
			for _, path := range msg.Paths {
				if path != nil && !path.IsEOR() {
					paths = append(paths, path)
				}
			}
		case <-time.After(quiet):
			return paths
		case <-deadline:
			return paths
		}
	}
}

// assertNoOutgoing verifies the peer has nothing queued to send.
func (h *llgrTestHarness) assertNoOutgoing(p *peer) {
	h.t.Helper()
	select {
	case o := <-p.fsm.outgoingCh.Out():
		h.t.Fatalf("unexpected outgoing UPDATE: %#v", o)
	case <-time.After(150 * time.Millisecond):
	}
}

// snapshotEvents returns a copy of every best-path FIB event collected so
// far. Watcher events are forwarded through an InfiniteChannel by a
// separate goroutine, so callers should wait for the event they expect with
// waitForEvents rather than reading immediately after ingest.
func (h *llgrTestHarness) snapshotEvents() []*watchEventBestPath {
	h.mu.Lock()
	defer h.mu.Unlock()
	snapshot := make([]*watchEventBestPath, len(h.events))
	copy(snapshot, h.events)
	return snapshot
}

// waitForEvents blocks until at least n FIB events for the prefix have been
// observed, or fails the test after the deadline.
func (h *llgrTestHarness) waitForEvents(prefix string, n int) {
	h.t.Helper()
	assert.Eventually(h.t, func() bool {
		return len(h.eventsFor(prefix)) >= n
	}, 2*time.Second, 5*time.Millisecond)
}

// bestPathEventsFor returns every queued FIB event for the prefix.
func (h *llgrTestHarness) eventsFor(prefix string) []*watchEventBestPath {
	h.t.Helper()
	out := make([]*watchEventBestPath, 0)
	for _, ev := range h.snapshotEvents() {
		match := false
		for _, check := range [][][]*table.Path{ev.MultiPathList} {
			for _, group := range check {
				for _, p := range group {
					if p.GetPrefix() == prefix {
						match = true
					}
				}
			}
		}
		for _, p := range append(append([]*table.Path{}, ev.UpdatePathList...), ev.WithdrawPathList...) {
			if p.GetPrefix() == prefix {
				match = true
			}
		}
		if match {
			out = append(out, ev)
		}
	}
	return out
}

// TestLLGRMultipath_FreshPathExcludesStale drives the cutover sequence and
// proves the FIB-facing multipath set never contains the stale next hop
// while a fresh path exists.
func TestLLGRMultipath_FreshPathExcludesStale(t *testing.T) {
	h := newLLGRTestHarness(t)
	peerA := h.addSourcePeer("A", "10.0.0.11", 65010)
	peerB := h.addSourcePeer("B", "10.0.0.12", 65011)
	llgrPeer := h.addDownstreamPeer("llgr", "10.0.0.21", 65020, true, 0)
	plainPeer := h.addDownstreamPeer("plain", "10.0.0.22", 65021, false, 0)

	// Both campuses initially advertise the prefix: two-way ECMP.
	h.ingest(peerA, learnPath(t, peerA, llgrMultipathPrefixV4, "10.0.0.11", false))
	h.drainOutgoing(llgrPeer)
	h.drainOutgoing(plainPeer)
	h.ingest(peerB, learnPath(t, peerB, llgrMultipathPrefixV4, "10.0.0.12", false))
	assert.ElementsMatch(t, []string{"10.0.0.11", "10.0.0.12"}, h.multipathNextHops(llgrMultipathPrefixV4))
	h.drainOutgoing(llgrPeer)
	h.drainOutgoing(plainPeer)

	// Campus B loses its session (LLGR): its path is marked stale. Campus A
	// is still fresh, so multipath must collapse to A alone.
	h.enterLLGR(peerB)
	assert.Equal(t, []string{"10.0.0.11"}, h.multipathNextHops(llgrMultipathPrefixV4))

	// The best path itself did not change, so downstream peers get nothing.
	h.assertNoOutgoing(llgrPeer)
	h.assertNoOutgoing(plainPeer)

	// Every FIB event observed for the prefix must reference only the fresh
	// next hop after the reset; the stale NH may only appear as a withdraw.
	for _, ev := range h.eventsFor(llgrMultipathPrefixV4) {
		for _, group := range ev.MultiPathList {
			for _, p := range group {
				assert.False(t, p.IsLLGRStale() && !p.IsWithdraw,
					"stale path %s installed by FIB event alongside a fresh path", p.GetNexthop())
			}
		}
	}

	// Campus A also resets: with no fresh alternative the two stale paths
	// keep the LLGR degraded multipath semantics.
	h.enterLLGR(peerA)
	assert.ElementsMatch(t, []string{"10.0.0.11", "10.0.0.12"}, h.multipathNextHops(llgrMultipathPrefixV4))

	// LLGR-capable downstream keeps the (now stale) best path; the peer
	// without LLGR receives a single withdrawal instead.
	llgrOut := h.drainOutgoing(llgrPeer)
	require.Len(t, llgrOut, 1)
	assert.False(t, llgrOut[0].IsWithdraw)
	assert.True(t, llgrOut[0].IsLLGRStale())
	plainOut := h.drainOutgoing(plainPeer)
	require.Len(t, plainOut, 1)
	assert.True(t, plainOut[0].IsWithdraw)

	// Campus A returns with a fresh path: multipath collapses back to A;
	// the stale B next hop is withdrawn from the FIB exactly once.
	h.ingest(peerA, learnPath(t, peerA, llgrMultipathPrefixV4, "10.0.0.11", false))
	h.waitForEvents(llgrMultipathPrefixV4, 5)
	assert.Equal(t, []string{"10.0.0.11"}, h.multipathNextHops(llgrMultipathPrefixV4))

	var staleWithdraws int
	for _, ev := range h.eventsFor(llgrMultipathPrefixV4) {
		for _, p := range ev.WithdrawPathList {
			if p.IsLLGRStale() && p.GetNexthop().String() == "10.0.0.12" {
				staleWithdraws++
			}
		}
	}
	assert.Equal(t, 1, staleWithdraws, "stale multipath NH must be withdrawn exactly once")
}

// TestLLGRMultipath_OutOfOrderWithdraw proves that losing the fresh path
// before the stale one falls back to degraded forwarding instead of
// declaring the destination dead, and that the final withdraw empties it.
func TestLLGRMultipath_OutOfOrderWithdraw(t *testing.T) {
	h := newLLGRTestHarness(t)
	peerA := h.addSourcePeer("A", "10.0.0.11", 65010)
	peerB := h.addSourcePeer("B", "10.0.0.12", 65011)
	llgrPeer := h.addDownstreamPeer("llgr", "10.0.0.21", 65020, true, 0)

	pA := learnPath(t, peerA, llgrMultipathPrefixV4, "10.0.0.11", false)
	pB := learnPath(t, peerB, llgrMultipathPrefixV4, "10.0.0.12", false)
	h.ingest(peerA, pA)
	h.drainOutgoing(llgrPeer)
	h.ingest(peerB, pB)
	h.drainOutgoing(llgrPeer)
	h.enterLLGR(peerB)
	h.assertNoOutgoing(llgrPeer)
	assert.Equal(t, []string{"10.0.0.11"}, h.multipathNextHops(llgrMultipathPrefixV4))

	// Withdraw the fresh path first (out-of-order control plane event).
	h.ingest(peerA, pA.Clone(true))
	assert.Equal(t, []string{"10.0.0.12"}, h.multipathNextHops(llgrMultipathPrefixV4),
		"stale path must take over in degraded mode after fresh withdraw")
	out := h.drainOutgoing(llgrPeer)
	require.Len(t, out, 1)
	assert.False(t, out[0].IsWithdraw)
	assert.True(t, out[0].IsLLGRStale())

	// Then the stale path disappears: the destination drains.
	h.s.dropAdjRIBIn(peerB, []bgp.Family{bgp.RF_IPv4_UC})
	assert.Empty(t, h.multipathNextHops(llgrMultipathPrefixV4))
	out = h.drainOutgoing(llgrPeer)
	require.Len(t, out, 1)
	assert.True(t, out[0].IsWithdraw)
}

// TestLLGRMultipath_SimultaneousConvergence resets several source peers
// concurrently and races a fresh advertisement against the stale
// transitions: the multipath result must deterministically converge to the
// single fresh next hop. Run with -race.
func TestLLGRMultipath_SimultaneousConvergence(t *testing.T) {
	h := newLLGRTestHarness(t)
	const n = 4
	peers := make([]*peer, n)
	paths := make([]*table.Path, n)
	for i := range n {
		addr := netip.AddrFrom4([4]byte{10, 0, 1, byte(10 + i)}).String()
		peers[i] = h.addSourcePeer(string(rune('A'+i)), addr, uint32(65010+i))
		paths[i] = learnPath(t, peers[i], llgrMultipathPrefixV4, addr, false)
		h.ingest(peers[i], paths[i])
	}
	require.Len(t, h.multipathNextHops(llgrMultipathPrefixV4), n)
	for _, p := range h.dwn {
		h.drainOutgoing(p)
	}

	var wg sync.WaitGroup
	// Peers B/C/D reset (stale) while A re-advertises fresh concurrently.
	wg.Add(1)
	go func() { defer wg.Done(); h.enterLLGR(peers[0]); h.ingest(peers[0], paths[0]) }()
	for i := 1; i < n; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); h.enterLLGR(peers[i]) }(i)
	}
	wg.Wait()

	// Whether A's reset+relearn or the others' resets is processed last,
	// the final state must be: A fresh is the sole multipath NH.
	assert.Eventually(t, func() bool {
		nhs := h.multipathNextHops(llgrMultipathPrefixV4)
		return len(nhs) == 1 && nhs[0] == "10.0.1.10"
	}, time.Second, 5*time.Millisecond)
	assert.Equal(t, []string{"10.0.1.10"}, h.multipathNextHops(llgrMultipathPrefixV4))
}

// TestLLGRMultipath_PolicyRecomputeNoSpuriousWithdraw recomputes the RIB
// outbound (soft reset out, as an export-policy change triggers) at each
// stage of the fresh/stale transition. Recomputation must never advertise
// the stale path while a fresh one exists, and must not manufacture
// withdraws when the decision is unchanged.
func TestLLGRMultipath_PolicyRecomputeNoSpuriousWithdraw(t *testing.T) {
	h := newLLGRTestHarness(t)
	peerA := h.addSourcePeer("A", "10.0.0.11", 65010)
	peerB := h.addSourcePeer("B", "10.0.0.12", 65011)
	llgrPeer := h.addDownstreamPeer("llgr", "10.0.0.21", 65020, true, 0)

	h.ingest(peerA, learnPath(t, peerA, llgrMultipathPrefixV4, "10.0.0.11", false))
	h.ingest(peerB, learnPath(t, peerB, llgrMultipathPrefixV4, "10.0.0.12", false))
	h.drainOutgoing(llgrPeer)

	h.enterLLGR(peerB)
	h.drainOutgoing(llgrPeer) // best unchanged: nothing expected; drain just in case

	// Recompute while A is fresh, B stale: only the fresh best is sent and
	// no withdrawal appears. (The outbound next hop is rewritten by
	// next-hop-self, so identify the route by its source and prefix.)
	require.NoError(t, h.s.softResetOut("10.0.0.21", bgp.RF_IPv4_UC, false))
	out := h.drainOutgoing(llgrPeer)
	var adv, withdraw int
	for _, p := range out {
		if p.IsWithdraw {
			withdraw++
			continue
		}
		adv++
		assert.Equal(t, "10.0.0.11", p.GetSource().Address.String())
		assert.False(t, p.IsLLGRStale())
	}
	assert.Equal(t, 1, adv, "recompute must advertise the fresh best once")
	assert.Zero(t, withdraw, "recompute with unchanged decision must not withdraw")

	// Recompute again: idempotent, still no withdraw.
	require.NoError(t, h.s.softResetOut("10.0.0.21", bgp.RF_IPv4_UC, false))
	for _, p := range h.drainOutgoing(llgrPeer) {
		assert.False(t, p.IsWithdraw)
	}
}

// TestLLGRMultipath_AddPathNoSpuriousWithdraw exercises an ADD-PATH
// downstream with a send-max above the path count. The stale/fresh
// transitions must not withdraw paths that remain valid candidates, and
// must never send a duplicate withdraw.
func TestLLGRMultipath_AddPathNoSpuriousWithdraw(t *testing.T) {
	h := newLLGRTestHarness(t)
	peerA := h.addSourcePeer("A", "10.0.0.11", 65010)
	peerB := h.addSourcePeer("B", "10.0.0.12", 65011)
	addPeer := h.addDownstreamPeer("addpath", "10.0.0.21", 65020, true, 8)

	h.ingest(peerA, learnPath(t, peerA, llgrMultipathPrefixV4, "10.0.0.11", false))
	h.drainOutgoing(addPeer)
	h.ingest(peerB, learnPath(t, peerB, llgrMultipathPrefixV4, "10.0.0.12", false))
	h.drainOutgoing(addPeer)

	// B goes stale: under ADD-PATH the stale route is still a valid distinct
	// path for an LLGR-capable receiver and must not be withdrawn merely
	// because multipath collapsed locally.
	h.enterLLGR(peerB)
	for _, p := range h.drainOutgoing(addPeer) {
		assert.False(t, p.IsWithdraw, "LLGR stale ADD-PATH entry must not be withdrawn")
	}

	// A flips stale and comes back fresh: the churn must withdraw nothing
	// (B's stale entry remains valid; A's entry is replaced in place).
	h.enterLLGR(peerA)
	h.drainOutgoing(addPeer)
	h.ingest(peerA, learnPath(t, peerA, llgrMultipathPrefixV4, "10.0.0.11", false))
	for _, p := range h.drainOutgoing(addPeer) {
		assert.False(t, p.IsWithdraw, "fresh re-advertisement must not produce withdraws")
	}

	// Real withdrawal of B produces exactly one withdraw for its path.
	// Identify it by its source address: the outbound next hop itself is
	// rewritten by next-hop-self before emission.
	h.s.dropAdjRIBIn(peerB, []bgp.Family{bgp.RF_IPv4_UC})
	var withdraws int
	for _, p := range h.drainOutgoing(addPeer) {
		if p.IsWithdraw {
			withdraws++
			assert.Equal(t, "10.0.0.12", p.GetSource().Address.String())
		}
	}
	assert.Equal(t, 1, withdraws)
}

// TestLLGRMultipath_NonLLGRFamilyAndNeighbor bounds the blast radius:
//   - a fresh route is advertised to a non-LLGR neighbor normally;
//   - once the same route is stale, the non-LLGR neighbor gets one
//     withdrawal (RFC 9494 4.3), never a stale advertisement;
//   - an IPv6 route whose family is not in the LLGR set is dropped on
//     reset and withdrawn exactly once; the IPv4 decision is untouched by
//     the IPv6 event.
func TestLLGRMultipath_NonLLGRFamilyAndNeighbor(t *testing.T) {
	h := newLLGRTestHarness(t)
	peerA := h.addSourcePeer("A", "10.0.0.11", 65010)
	plainPeer := h.addDownstreamPeer("plain", "10.0.0.22", 65021, false, 0)

	v4 := learnPath(t, peerA, llgrMultipathPrefixV4, "10.0.0.11", false)
	v6 := learnPath(t, peerA, llgrMultipathPrefixV6, "2001:db8::1", false)
	h.ingest(peerA, v4)
	h.ingest(peerA, v6)

	out := h.drainOutgoing(plainPeer)
	var sawV4, sawV6 bool
	for _, p := range out {
		assert.False(t, p.IsWithdraw)
		if p.GetPrefix() == llgrMultipathPrefixV4 {
			sawV4 = true
		}
		if p.GetPrefix() == llgrMultipathPrefixV6 {
			sawV6 = true
		}
	}
	assert.True(t, sawV4 && sawV6, "fresh routes for both families advertised normally")

	// IPv4 enters LLGR: non-LLGR neighbor must withdraw the stale route
	// exactly once and never receive the stale advertisement.
	h.enterLLGR(peerA)
	v4Withdraws := 0
	for _, p := range h.drainOutgoing(plainPeer) {
		if p.GetPrefix() == llgrMultipathPrefixV4 {
			assert.True(t, p.IsWithdraw)
			assert.False(t, p.IsLLGRStale() && !p.IsWithdraw)
			v4Withdraws++
		}
	}
	assert.Equal(t, 1, v4Withdraws)
	assert.Equal(t, []string{"10.0.0.11"}, h.multipathNextHops(llgrMultipathPrefixV4))

	// IPv6 is not part of the LLGR set for this peer: on reset it is
	// dropped and withdrawn once; the IPv4 stale decision is unaffected.
	h.s.dropAdjRIBIn(peerA, []bgp.Family{bgp.RF_IPv6_UC})
	v6Withdraws := 0
	for _, p := range h.drainOutgoing(plainPeer) {
		if p.GetPrefix() == llgrMultipathPrefixV6 {
			assert.True(t, p.IsWithdraw)
			v6Withdraws++
		}
		if p.GetPrefix() == llgrMultipathPrefixV4 {
			assert.Fail(t, "IPv6 drop must not alter the IPv4 advertisement")
		}
	}
	assert.Equal(t, 1, v6Withdraws)
	assert.Equal(t, []string{"10.0.0.11"}, h.multipathNextHops(llgrMultipathPrefixV4))
}
