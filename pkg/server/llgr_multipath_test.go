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

// llgrMultipathSuite wires a multipath-enabled server with two upstream
// eBGP peers (the two campus exits in the incident) and watchers.
type llgrMultipathSuite struct {
	t      *testing.T
	s      *BgpServer
	p1, p2 *peer
	watch  *watcher

	mu     sync.Mutex
	events []*watchEventBestPath
}

func newLLGRMultipathSuite(t *testing.T) *llgrMultipathSuite {
	t.Helper()
	ctx := context.Background()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:              65000,
			RouterId:         "10.0.0.1",
			ListenPort:       -1,
			UseMultiplePaths: true,
		},
	}))
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(ctx, &api.StopBgpRequest{}))
	})

	// Import/export default accept so the synthetic paths propagate.
	require.NoError(t, s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          table.GLOBAL_RIB_NAME,
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			DefaultAction: api.RouteAction_ROUTE_ACTION_ACCEPT,
		},
	}))

	p1 := newPeerandInfo(t, 65000, 65100, "10.0.1.1", s.globalRib)
	p2 := newPeerandInfo(t, 65000, 65100, "10.0.1.2", s.globalRib)

	w, err := s.watch(WatchBestPath(false))
	require.NoError(t, err)
	t.Cleanup(w.Stop)

	su := &llgrMultipathSuite{t: t, s: s, p1: p1, p2: p2, watch: w}
	go func() {
		for ev := range w.Event() {
			if b, ok := ev.(*watchEventBestPath); ok {
				su.mu.Lock()
				su.events = append(su.events, b)
				su.mu.Unlock()
			}
		}
	}()
	return su
}

func (su *llgrMultipathSuite) propagate(peer *peer, paths ...*table.Path) {
	su.t.Helper()
	su.s.propagateUpdate(peer, paths)
}

// drainEvents returns the best-path events that settled after the last
// propagation and resets the buffer.
func (su *llgrMultipathSuite) drainEvents() []*watchEventBestPath {
	su.t.Helper()
	time.Sleep(100 * time.Millisecond)
	su.mu.Lock()
	defer su.mu.Unlock()
	evs := su.events
	su.events = nil
	return evs
}

func llgrPeerPath(t *testing.T, p *peer, family bgp.Family, prefix, nexthop string, stale bool) *table.Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	base := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65100}),
		}),
	}
	var attrs []bgp.PathAttributeInterface
	switch family {
	case bgp.RF_IPv4_UC:
		nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
		require.NoError(t, err)
		attrs = append(base, nh)
	case bgp.RF_IPv6_UC:
		mpreach, err := bgp.NewPathAttributeMpReachNLRI(family,
			[]bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(nexthop))
		require.NoError(t, err)
		attrs = append(base, mpreach)
	default:
		t.Fatalf("unsupported family %s", family)
	}
	if stale {
		attrs = append(attrs, bgp.NewPathAttributeCommunities([]uint32{
			uint32(bgp.COMMUNITY_LLGR_STALE),
		}))
	}
	return table.NewPath(family, p.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

// addDownstream registers an established synthetic iBGP downstream peer.
func (su *llgrMultipathSuite) addDownstream(address string, asn uint32, llgr, addPath bool, sendMax uint8) *peer {
	su.t.Helper()
	target := newPeerandInfo(su.t, 65000, asn, address, su.s.globalRib)
	target.policy = su.s.policy
	target.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	mode := bgp.BGP_ADD_PATH_NONE
	if addPath {
		mode = bgp.BGP_ADD_PATH_SEND
	}
	target.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{
		bgp.RF_IPv4_UC: mode,
		bgp.RF_IPv6_UC: mode,
	})
	target.fsm.lock.Lock()
	conf := target.fsm.pConf.ReadCopy()
	// The synthetic peer is created from an IPv4 address, so defaults only
	// provision the IPv4 unicast AFI-SAFI. Add IPv6 explicitly so the
	// add-path/LLGR knobs apply to both families.
	hasV6 := false
	for i := range conf.AfiSafis {
		if conf.AfiSafis[i].State.Family == bgp.RF_IPv6_UC {
			hasV6 = true
		}
	}
	if !hasV6 {
		v6 := oc.AfiSafi{
			Config: oc.AfiSafiConfig{AfiSafiName: oc.AFI_SAFI_TYPE_IPV6_UNICAST, Enabled: true},
			State:  oc.AfiSafiState{AfiSafiName: oc.AFI_SAFI_TYPE_IPV6_UNICAST, Family: bgp.RF_IPv6_UC},
		}
		conf.AfiSafis = append(conf.AfiSafis, v6)
	}
	for i := range conf.AfiSafis {
		switch conf.AfiSafis[i].State.Family {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			if addPath {
				conf.AfiSafis[i].AddPaths.Config.SendMax = sendMax
				conf.AfiSafis[i].AddPaths.State.SendMax = sendMax
			}
			if llgr {
				conf.GracefulRestart.Config.LongLivedEnabled = true
				conf.AfiSafis[i].LongLivedGracefulRestart.State.Enabled = true
			}
		}
	}
	target.fsm.pConf.Update(&conf)
	target.fsm.lock.Unlock()

	addr := netip.MustParseAddr(address)
	require.NoError(su.t, su.s.mgmtOperation(func() error {
		su.s.neighborMap[addr] = target
		return nil
	}, true))
	su.t.Cleanup(func() {
		_ = su.s.mgmtOperation(func() error {
			delete(su.s.neighborMap, addr)
			return nil
		}, false)
		cleanInfiniteChannel(target.fsm.outgoingCh)
	})
	return target
}

// drainOutgoing gathers every outbound message that settles after a
// propagation round; best-path changes can split into one message per path.
func drainOutgoing(t *testing.T, p *peer) []*table.Path {
	t.Helper()
	var paths []*table.Path
	deadline := time.After(400 * time.Millisecond)
	for {
		select {
		case o := <-p.fsm.outgoingCh.Out():
			msg, ok := o.(*fsmOutgoingMsg)
			require.True(t, ok)
			for _, path := range msg.Paths {
				if path != nil && !path.IsEOR() {
					paths = append(paths, path)
				}
			}
		case <-deadline:
			return paths
		}
	}
}

func requireNoOutgoing(t *testing.T, p *peer) {
	t.Helper()
	select {
	case o := <-p.fsm.outgoingCh.Out():
		t.Fatalf("unexpected outbound paths: %#v", o)
	case <-time.After(200 * time.Millisecond):
	}
}

// eventNexthops extracts multipath nexthops for prefix from one event.
func eventNexthops(ev *watchEventBestPath, prefix string) []string {
	out := make([]string, 0)
	for _, paths := range ev.MultiPathList {
		for _, p := range paths {
			if p.GetPrefix() == prefix {
				out = append(out, p.GetNexthop().String())
			}
		}
	}
	return out
}

func pathNexthops(paths []*table.Path) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, p.GetNexthop().String())
	}
	return out
}

func multipathDelta(ev *watchEventBestPath, prefix string) (updates, withdrawals []string) {
	for _, p := range ev.UpdatePathList {
		if p.GetPrefix() == prefix {
			updates = append(updates, p.GetNexthop().String())
		}
	}
	for _, p := range ev.WithdrawPathList {
		if p.GetPrefix() == prefix {
			withdrawals = append(withdrawals, p.GetNexthop().String())
		}
	}
	return
}

const (
	llgrPrefixV4 = "10.10.0.0/24"
	nh1          = "192.0.2.1"
	nh2          = "192.0.2.2"
)

// TestLLGRMultipathIntegration is the end-to-end regression for the live
// cutover incident: two equal-cost exits, one of them enters LLGR. The
// stale nexthop must leave the multipath set immediately, come back only
// after a fresh re-advertisement, and all-stale convergence keeps the
// degraded semantics. The multipath delta to watchers (zebra/BMP) and the
// ADD-PATH downstream must agree.
func TestLLGRMultipathIntegration(t *testing.T) {
	su := newLLGRMultipathSuite(t)

	// ADD-PATH downstream sees every multipath member; the old bug handed
	// it the stale nexthop as a live path.
	addPeer := su.addDownstream("10.0.2.1", 65000, false, true, 4)
	// Non-ADD-PATH downstream tracks only the single best path.
	bestOnly := su.addDownstream("10.0.2.2", 65000, false, false, 0)

	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, llgrPrefixV4, nh1, false))
	su.propagate(su.p2, llgrPeerPath(t, su.p2, bgp.RF_IPv4_UC, llgrPrefixV4, nh2, false))
	su.drainEvents()
	assert.ElementsMatch(t, []string{nh1, nh2}, pathNexthops(drainOutgoing(t, addPeer)))
	firstBest := drainOutgoing(t, bestOnly)
	require.Len(t, firstBest, 1)
	assert.False(t, firstBest[0].IsWithdraw)

	// Exit 1 enters LLGR: its path is replaced by its LLGR_STALE clone.
	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, llgrPrefixV4, nh1, true))
	evs := su.drainEvents()
	require.NotEmpty(t, evs)
	for _, ev := range evs {
		assert.Equal(t, []string{nh2}, eventNexthops(ev, llgrPrefixV4),
			"stale nexthop must never share a multipath set with the fresh one")
		u, w := multipathDelta(ev, llgrPrefixV4)
		assert.Empty(t, u, "surviving fresh path must not be re-installed")
		for _, withdrawn := range w {
			assert.Equal(t, nh1, withdrawn)
		}
	}

	// ADD-PATH downstream: the stale local-id is turned into a withdrawal
	// (the peer is not LLGR capable); nh2 stays installed.
	out := drainOutgoing(t, addPeer)
	require.Len(t, out, 1)
	assert.True(t, out[0].IsWithdraw)
	assert.Equal(t, nh1, out[0].GetNexthop().String())
	// Best moved from nh1 to the surviving nh2: one announcement, no withdraw.
	out = drainOutgoing(t, bestOnly)
	require.Len(t, out, 1)
	assert.False(t, out[0].IsWithdraw)
	assert.Equal(t, nh2, out[0].GetNexthop().String())

	// Exit 1 re-establishes fresh: multipath restored by an update for nh1
	// with no withdrawal of nh2.
	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, llgrPrefixV4, nh1, false))
	evs = su.drainEvents()
	last := evs[len(evs)-1]
	u, w := multipathDelta(last, llgrPrefixV4)
	assert.Equal(t, []string{nh1}, u)
	assert.Empty(t, w)
	out = drainOutgoing(t, addPeer)
	require.Len(t, out, 1)
	assert.False(t, out[0].IsWithdraw)
	assert.Equal(t, nh1, out[0].GetNexthop().String())
	requireNoOutgoing(t, bestOnly)

	// Both exits enter LLGR one after the other: while nh2 is fresh, nh1's
	// stale clone stays out of the multipath set; once both are stale, LLGR
	// degradation keeps forwarding over both stale paths.
	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, llgrPrefixV4, nh1, true))
	assert.Equal(t, [][]string{{nh2}}, collectNexthops(su.drainEvents(), llgrPrefixV4))
	drainOutgoing(t, addPeer) // stale nh1 re-announce -> withdrawal on non-LLGR peer
	requireNoOutgoing(t, bestOnly)

	su.propagate(su.p2, llgrPeerPath(t, su.p2, bgp.RF_IPv4_UC, llgrPrefixV4, nh2, true))
	evs = su.drainEvents()
	last = evs[len(evs)-1]
	assert.ElementsMatch(t, []string{nh1, nh2}, eventNexthops(last, llgrPrefixV4),
		"all-stale multipath must survive in LLGR degradation mode")
	for _, paths := range last.MultiPathList {
		for _, p := range paths {
			if p.GetPrefix() == llgrPrefixV4 {
				assert.True(t, p.IsLLGRStale())
			}
		}
	}
	// Degradation delta re-announces stale paths but withdraws nothing.
	_, w = multipathDelta(last, llgrPrefixV4)
	assert.Empty(t, w)
}

func collectNexthops(evs []*watchEventBestPath, prefix string) [][]string {
	out := make([][]string, 0, len(evs))
	for _, ev := range evs {
		if nh := eventNexthops(ev, prefix); len(nh) > 0 {
			out = append(out, nh)
		}
	}
	return out
}

// TestLLGRMultipathTimerTransitions replays the LLGR timer bookkeeping
// (GR-expiry mark-stale, then LLGR-restart-timer expiry drop) against one
// LLGR-capable and one plain downstream. The capable peer retains the stale
// route and withdraws it only at final drop; the plain peer never receives
// a stale advertisement. Watcher deltas contain no withdrawals while the
// stale route remains best.
func TestLLGRMultipathTimerTransitions(t *testing.T) {
	su := newLLGRMultipathSuite(t)
	const prefix = "10.20.0.0/24"

	llgrPeer := su.addDownstream("10.0.3.1", 65000, true, false, 0)
	plainPeer := su.addDownstream("10.0.3.2", 65000, false, false, 0)

	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, false))
	su.drainEvents()
	for _, p := range []*peer{llgrPeer, plainPeer} {
		out := drainOutgoing(t, p)
		require.Len(t, out, 1)
		assert.False(t, out[0].IsWithdraw)
	}

	// GR timer expires, LLGR starts: path re-announced with LLGR_STALE.
	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, true))
	evs := su.drainEvents()
	last := evs[len(evs)-1]
	// Stale stays best (only candidate); the multipath delta must not withdraw.
	_, w := multipathDelta(last, prefix)
	assert.Empty(t, w, "stale best retained during LLGR must not be withdrawn from the RIB")

	out := drainOutgoing(t, llgrPeer)
	require.Len(t, out, 1)
	assert.False(t, out[0].IsWithdraw)
	assert.True(t, out[0].IsLLGRStale(), "LLGR-capable peer retains the stale route")

	for _, p := range drainOutgoing(t, plainPeer) {
		assert.True(t, p.IsWithdraw, "plain peer must only see withdrawals, never the stale route")
	}

	// LLGR restart timer expiry drops the path: final, single withdrawal to
	// the LLGR-capable peer.
	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, true).Clone(true))
	su.drainEvents()
	out = drainOutgoing(t, llgrPeer)
	require.Len(t, out, 1)
	assert.True(t, out[0].IsWithdraw)
	assert.Equal(t, prefix, out[0].GetPrefix())
	// The plain peer already withdrew at stale-marking time; it must not see
	// the final drop as a second withdrawal.
	requireNoOutgoing(t, plainPeer)
}

// TestLLGRMultipathNoSpuriousWithdrawals covers the two ways timer
// transitions used to generate extra withdrawals toward ADD-PATH peers:
//   - a stale path that was never advertised (it lingers behind a fresh best
//     or the peer joined while the route was already stale) must not be
//     withdrawn when it is marked LLGR_STALE;
//   - the LLGR-restart-timer drop of a stale path must not withdraw it a
//     second time after the stale-marking step already withdrew it.
func TestLLGRMultipathNoSpuriousWithdrawals(t *testing.T) {
	t.Run("never-advertised stale path", func(t *testing.T) {
		su := newLLGRMultipathSuite(t)
		const prefix = "10.50.0.0/24"
		addPeer := su.addDownstream("10.0.6.1", 65000, false, true, 4)

		// The peer first learns the prefix while p1 is already in LLGR: the
		// stale path is briefly best, but it was never in this peer's
		// RIB-out, so nothing (in particular no withdrawal) must be sent.
		su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, true))
		su.drainEvents()
		requireNoOutgoing(t, addPeer)

		// A fresh alternative from p2 becomes best and is advertised once.
		su.propagate(su.p2, llgrPeerPath(t, su.p2, bgp.RF_IPv4_UC, prefix, nh2, false))
		su.drainEvents()
		out := drainOutgoing(t, addPeer)
		require.Len(t, out, 1)
		assert.False(t, out[0].IsWithdraw)
		assert.Equal(t, nh2, out[0].GetNexthop().String())

		// Any later re-evaluation of the lingering stale path (e.g. import
		// policy recompute triggering another propagation) stays silent.
		su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, true))
		su.drainEvents()
		requireNoOutgoing(t, addPeer)
	})

	t.Run("timer drop does not double withdraw", func(t *testing.T) {
		su := newLLGRMultipathSuite(t)
		const prefix = "10.50.1.0/24"
		// Plain (non-LLGR) ADD-PATH peer: it must withdraw the route when it
		// is marked stale, but only once.
		addPeer := su.addDownstream("10.0.6.2", 65000, false, true, 4)

		su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, false))
		su.drainEvents()
		out := drainOutgoing(t, addPeer)
		require.Len(t, out, 1)
		assert.False(t, out[0].IsWithdraw)

		// GR expiry marks the path LLGR_STALE: exactly one withdrawal.
		stale := llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, true)
		su.propagate(su.p1, stale)
		su.drainEvents()
		out = drainOutgoing(t, addPeer)
		require.Len(t, out, 1)
		assert.True(t, out[0].IsWithdraw)
		assert.Equal(t, prefix, out[0].GetPrefix())

		// LLGR restart timer expiry drops the path: no second withdrawal.
		su.propagate(su.p1, stale.Clone(true))
		su.drainEvents()
		requireNoOutgoing(t, addPeer)
	})

	t.Run("timer drop does not double withdraw non-add-path", func(t *testing.T) {
		su := newLLGRMultipathSuite(t)
		const prefix = "10.50.2.0/24"
		// Same sequence against a non-ADD-PATH plain peer, where the stale
		// marking takes the best-change withdrawal path.
		plainPeer := su.addDownstream("10.0.6.3", 65000, false, false, 0)

		su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, false))
		su.drainEvents()
		require.Len(t, drainOutgoing(t, plainPeer), 1)

		stale := llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, true)
		su.propagate(su.p1, stale)
		su.drainEvents()
		out := drainOutgoing(t, plainPeer)
		require.Len(t, out, 1)
		assert.True(t, out[0].IsWithdraw)

		// Timer expiry: best disappears entirely. The withdrawal produced by
		// GetChanges must be suppressed because RIB-out no longer holds it.
		su.propagate(su.p1, stale.Clone(true))
		su.drainEvents()
		requireNoOutgoing(t, plainPeer)
	})
}

// TestLLGRMultipathPolicyRecompute verifies export-policy recompute while a
// stale path lingers behind a fresh best: soft reset out neither leaks the
// stale route nor double-withdraws the fresh best when policy rejects it.
func TestLLGRMultipathPolicyRecompute(t *testing.T) {
	ctx := context.Background()
	su := newLLGRMultipathSuite(t)
	const prefix = "10.30.0.0/24"
	plainPeer := su.addDownstream("10.0.4.2", 65000, false, false, 0)

	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, false))
	su.drainEvents()
	drainOutgoing(t, plainPeer)

	// p1 enters LLGR before the fresh backup is in place: the stale path is
	// best briefly and gets withdrawn from the non-LLGR downstream.
	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, true))
	su.drainEvents()
	for _, p := range drainOutgoing(t, plainPeer) {
		assert.True(t, p.IsWithdraw)
	}

	// p2's fresh path arrives and wins: exactly one fresh announcement.
	su.propagate(su.p2, llgrPeerPath(t, su.p2, bgp.RF_IPv4_UC, prefix, nh2, false))
	su.drainEvents()
	out := drainOutgoing(t, plainPeer)
	require.Len(t, out, 1)
	assert.False(t, out[0].IsWithdraw)
	assert.False(t, out[0].IsLLGRStale())
	assert.Equal(t, nh2, out[0].GetNexthop().String())

	// Recompute RIB-out with accept policy: the stale path is not part of the
	// re-advertised best.
	require.NoError(t, su.s.softResetOut("10.0.4.2", bgp.RF_IPv4_UC, false))
	for _, p := range drainOutgoing(t, plainPeer) {
		assert.False(t, p.IsLLGRStale(), "policy recompute must not leak the stale route")
		assert.Equal(t, nh2, p.GetNexthop().String())
	}

	// Reject everything and recompute: exactly one withdrawal of the best.
	require.NoError(t, su.s.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          table.GLOBAL_RIB_NAME,
			Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
			DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
	}))
	require.NoError(t, su.s.softResetOut("10.0.4.2", bgp.RF_IPv4_UC, false))
	var withdrawals int
	for _, p := range drainOutgoing(t, plainPeer) {
		if p.GetPrefix() == prefix && p.IsWithdraw {
			withdrawals++
		}
	}
	assert.Equal(t, 1, withdrawals, "fresh best withdrawn exactly once")

	// A second recompute changes nothing: no duplicate withdrawal.
	require.NoError(t, su.s.softResetOut("10.0.4.2", bgp.RF_IPv4_UC, false))
	requireNoOutgoing(t, plainPeer)
}

// TestLLGRMultipathSimultaneousConvergence fires both stale transitions
// concurrently. Every emitted multipath event must be internally
// consistent: a multipath set is all-fresh or all-stale, never the mixed
// state from the incident; convergence ends with both stale paths.
func TestLLGRMultipathSimultaneousConvergence(t *testing.T) {
	su := newLLGRMultipathSuite(t)
	const prefix = "10.40.0.0/24"

	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, false))
	su.propagate(su.p2, llgrPeerPath(t, su.p2, bgp.RF_IPv4_UC, prefix, nh2, false))
	su.drainEvents()

	stale1 := llgrPeerPath(t, su.p1, bgp.RF_IPv4_UC, prefix, nh1, true)
	stale2 := llgrPeerPath(t, su.p2, bgp.RF_IPv4_UC, prefix, nh2, true)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); su.propagate(su.p1, stale1) }()
	go func() { defer wg.Done(); su.propagate(su.p2, stale2) }()
	wg.Wait()

	evs := su.drainEvents()
	require.NotEmpty(t, evs)
	for _, ev := range evs {
		for _, paths := range ev.MultiPathList {
			var fresh, staleCount int
			for _, p := range paths {
				if p.GetPrefix() != prefix {
					continue
				}
				if p.IsLLGRStale() {
					staleCount++
				} else {
					fresh++
				}
			}
			assert.False(t, fresh > 0 && staleCount > 0,
				"fresh and stale paths must never coexist in one multipath event")
		}
	}
	last := evs[len(evs)-1]
	assert.ElementsMatch(t, []string{nh1, nh2}, eventNexthops(last, prefix))
}

// TestLLGRMultipathNonLLGRFamilyUnaffected proves the blast radius: for an
// address family without LLGR communities, ordinary equal-cost paths are
// still both selected and advertised, and a single path replacement emits
// no multipath withdrawal for the untouched equal path.
func TestLLGRMultipathNonLLGRFamilyUnaffected(t *testing.T) {
	su := newLLGRMultipathSuite(t)
	const prefix = "2001:db8::/64"
	const v6nh1, v6nh2 = "2001:db8::1", "2001:db8::2"
	addPeer := su.addDownstream("10.0.5.1", 65000, false, true, 4)

	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv6_UC, prefix, v6nh1, false))
	su.propagate(su.p2, llgrPeerPath(t, su.p2, bgp.RF_IPv6_UC, prefix, v6nh2, false))
	evs := su.drainEvents()
	last := evs[len(evs)-1]
	assert.ElementsMatch(t, []string{v6nh1, v6nh2}, eventNexthops(last, prefix),
		"ordinary IPv6 multipath must be unaffected by the LLGR fix")
	assert.ElementsMatch(t, []string{v6nh1, v6nh2}, pathNexthops(drainOutgoing(t, addPeer)))

	// A normal (non-LLGR) attribute update for p1's path must not generate a
	// withdrawal of p2's equal path.
	su.propagate(su.p1, llgrPeerPath(t, su.p1, bgp.RF_IPv6_UC, prefix, v6nh1, false))
	evs = su.drainEvents()
	for _, ev := range evs {
		_, w := multipathDelta(ev, prefix)
		assert.Empty(t, w, "ordinary re-advertisement must not withdraw equal paths")
	}
}
