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

package table

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// llgrTestPeer builds a distinct eBGP peer info for each address so that
// paths from different "campus exits" are multipath-eligible (same AS path
// length, MED, local-pref and origin apart from peer-address tie breaking).
func llgrTestPeer(address string) *PeerInfo {
	addr := netip.MustParseAddr(address)
	return &PeerInfo{
		AS:           65100,
		LocalAS:      65000,
		ID:           addr,
		Address:      addr,
		LocalID:      netip.MustParseAddr("10.0.0.1"),
		LocalAddress: netip.MustParseAddr("10.0.0.1"),
	}
}

func llgrMultipathPath(t *testing.T, peer *PeerInfo, prefix, nexthop string, stale bool) *Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65100}),
		}),
		nh,
		bgp.NewPathAttributeLocalPref(100),
	}
	if stale {
		attrs = append(attrs, bgp.NewPathAttributeCommunities([]uint32{
			uint32(bgp.COMMUNITY_LLGR_STALE),
		}))
	}
	return NewPath(bgp.RF_IPv4_UC, peer, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

func llgrMultipathManager(t *testing.T) *TableManager {
	t.Helper()
	return NewTableManager(slog.Default(),
		[]bgp.Family{bgp.RF_IPv4_UC},
		oc.RouteSelectionOptionsConfig{},
		oc.UseMultiplePathsConfig{Enabled: true})
}

// TestPathCompareLLGRStale pins the multipath equivalence predicate:
// an LLGR_STALE path can never be equivalent to a fresh path, while two
// stale paths can still compare equal (LLGR degradation mode).
func TestPathCompareLLGRStale(t *testing.T) {
	p1 := llgrTestPeer("10.0.1.1")
	p2 := llgrTestPeer("10.0.1.2")

	fresh := llgrMultipathPath(t, p1, "10.10.0.0/24", "192.0.2.1", false)
	stale := llgrMultipathPath(t, p2, "10.10.0.0/24", "192.0.2.2", true)

	// Fresh strictly beats stale regardless of comparison order.
	assert.Greater(t, fresh.Compare(stale), 0)
	assert.Less(t, stale.Compare(fresh), 0)

	// Two stale paths with identical decision metrics remain equal: this is
	// what keeps ECMP alive while every candidate is LLGR_STALE.
	stale2 := llgrMultipathPath(t, p2, "10.10.0.0/24", "192.0.2.2", true)
	assert.Equal(t, 0, stale2.Compare(stale))
}

// TestGetMultiBestPathExcludesLLGRStaleWithFreshBest is the minimal
// regression for the incident: sorted path order put the fresh path first,
// but the old equivalence predicate ignored LLGR_STALE so the stale path
// was admitted into the multipath set.
func TestGetMultiBestPathExcludesLLGRStaleWithFreshBest(t *testing.T) {
	fresh := llgrMultipathPath(t, llgrTestPeer("10.0.1.1"), "10.10.0.0/24", "192.0.2.1", false)
	stale := llgrMultipathPath(t, llgrTestPeer("10.0.1.2"), "10.10.0.0/24", "192.0.2.2", true)

	d := newDestination(fresh.GetNlri(), 0, fresh, stale)
	require.Equal(t, fresh, d.knownPathList[0], "fresh path must sort first")

	mp := d.GetMultiBestPath(GLOBAL_RIB_NAME)
	require.Len(t, mp, 1)
	assert.Equal(t, fresh, mp[0])
}

// TestGetMultiBestPathAllStaleKeepsDegradation verifies the LLGR fallback:
// with only stale candidates they must all stay eligible, otherwise traffic
// for the prefix would be dropped even though LLGR is explicitly retaining
// the routes for degraded forwarding.
func TestGetMultiBestPathAllStaleKeepsDegradation(t *testing.T) {
	stale1 := llgrMultipathPath(t, llgrTestPeer("10.0.1.1"), "10.10.0.0/24", "192.0.2.1", true)
	stale2 := llgrMultipathPath(t, llgrTestPeer("10.0.1.2"), "10.10.0.0/24", "192.0.2.2", true)

	d := newDestination(stale1.GetNlri(), 0, stale1, stale2)
	mp := d.GetMultiBestPath(GLOBAL_RIB_NAME)
	assert.Len(t, mp, 2)
}

// TestLLGRMultipathFreshPathDropsStale drives the full table manager flow
// that the GR timer transition performs: two fresh equal-cost paths, then
// one of them is replaced by its LLGR_STALE clone (same source). The stale
// path must leave the multipath set with a minimal delta (one withdraw, no
// churn for the surviving fresh path).
func TestLLGRMultipathFreshPathDropsStale(t *testing.T) {
	manager := llgrMultipathManager(t)
	peer1 := llgrTestPeer("10.0.1.1")
	peer2 := llgrTestPeer("10.0.1.2")

	fresh1 := llgrMultipathPath(t, peer1, "10.10.0.0/24", "192.0.2.1", false)
	fresh2 := llgrMultipathPath(t, peer2, "10.10.0.0/24", "192.0.2.2", false)

	dsts := manager.Update(fresh1)
	require.Len(t, dsts, 1)
	dsts = append(dsts, manager.Update(fresh2)...)

	updates := manager.GetBestMultiPathList(GLOBAL_RIB_NAME, []bgp.Family{bgp.RF_IPv4_UC})
	require.Len(t, updates, 1)
	require.Len(t, updates[0], 2, "both fresh paths start as multipath")

	// Peer1's session enters LLGR: its path is re-propagated with the
	// LLGR_STALE community attached (same source, implicit replacement).
	stale1 := llgrMultipathPath(t, peer1, "10.10.0.0/24", "192.0.2.1", true)
	dsts = manager.Update(stale1)
	require.Len(t, dsts, 1)

	updates = manager.GetBestMultiPathList(GLOBAL_RIB_NAME, []bgp.Family{bgp.RF_IPv4_UC})
	require.Len(t, updates, 1)
	require.Len(t, updates[0], 1, "stale path must leave the multipath set")
	assert.Equal(t, "192.0.2.2", updates[0][0].GetNexthop().String())

	u, w := dsts[0].GetMultiBestPathDiff(GLOBAL_RIB_NAME)
	assert.Empty(t, u, "the surviving fresh path must not be re-advertised")
	require.Len(t, w, 1, "the stale path must be withdrawn exactly once")
	assert.True(t, w[0].IsWithdraw)
	assert.Equal(t, "192.0.2.1", w[0].GetNexthop().String())

	// Peer1 comes back and advertises a fresh path again: the stale clone is
	// replaced and multipath returns to two paths via an update, without any
	// withdrawal for peer2's path.
	refreshed := llgrMultipathPath(t, peer1, "10.10.0.0/24", "192.0.2.1", false)
	dsts = manager.Update(refreshed)
	require.Len(t, dsts, 1)
	u, w = dsts[0].GetMultiBestPathDiff(GLOBAL_RIB_NAME)
	require.Len(t, u, 1)
	assert.False(t, u[0].IsWithdraw)
	assert.False(t, u[0].IsLLGRStale())
	assert.Empty(t, w)
}

// TestLLGRMultipathAllStaleStillForwarded exercises the degradation path
// end-to-end: when every peer is in LLGR, the stale paths must remain the
// (multipath) best paths and the transition must not generate withdrawals.
func TestLLGRMultipathAllStaleStillForwarded(t *testing.T) {
	manager := llgrMultipathManager(t)
	peer1 := llgrTestPeer("10.0.1.1")
	peer2 := llgrTestPeer("10.0.1.2")

	manager.Update(llgrMultipathPath(t, peer1, "10.10.0.0/24", "192.0.2.1", false))
	dsts := manager.Update(llgrMultipathPath(t, peer2, "10.10.0.0/24", "192.0.2.2", false))
	require.Len(t, dsts, 1)
	require.Len(t, getMultiBestPath(GLOBAL_RIB_NAME, dsts[0].KnownPathList), 2)

	// Both sessions enter LLGR one after the other, like timers expiring
	// independently on different peers.
	dsts = manager.Update(llgrMultipathPath(t, peer1, "10.10.0.0/24", "192.0.2.1", true))
	require.Len(t, dsts, 1)
	mp := getMultiBestPath(GLOBAL_RIB_NAME, dsts[0].KnownPathList)
	require.Len(t, mp, 1, "peer2 is still fresh: peer1's stale path cannot share ECMP")
	assert.Equal(t, "192.0.2.2", mp[0].GetNexthop().String())

	// Last fresh path becomes stale too: degradation mode now keeps both
	// stale paths as the multipath set instead of withdrawing everything.
	dsts = manager.Update(llgrMultipathPath(t, peer2, "10.10.0.0/24", "192.0.2.2", true))
	require.Len(t, dsts, 1)
	mp = getMultiBestPath(GLOBAL_RIB_NAME, dsts[0].KnownPathList)
	require.Len(t, mp, 2, "all-stale multipath must survive in degradation mode")
	assert.True(t, mp[0].IsLLGRStale())
	assert.True(t, mp[1].IsLLGRStale())

	u, w := dsts[0].GetMultiBestPathDiff(GLOBAL_RIB_NAME)
	// Degradation re-announces stale paths (with LLGR_STALE) but must not
	// withdraw anything.
	assert.Empty(t, w)
	for _, p := range u {
		assert.True(t, p.IsLLGRStale())
	}
}

// TestLLGRMultipathOutOfOrderWithdrawals replays withdrawals in orders that
// differ from the order the updates happened (as real BGP sessions deliver
// them across timers). None of them must resurrect a stale path into the
// multipath set or withdraw the surviving fresh path.
func TestLLGRMultipathOutOfOrderWithdrawals(t *testing.T) {
	manager := llgrMultipathManager(t)
	peer1 := llgrTestPeer("10.0.1.1")
	peer2 := llgrTestPeer("10.0.1.2")
	peer3 := llgrTestPeer("10.0.1.3")

	p1 := llgrMultipathPath(t, peer1, "10.10.0.0/24", "192.0.2.1", false)
	p2 := llgrMultipathPath(t, peer2, "10.10.0.0/24", "192.0.2.2", false)
	p3 := llgrMultipathPath(t, peer3, "10.10.0.0/24", "192.0.2.3", false)
	manager.Update(p1)
	manager.Update(p2)
	manager.Update(p3)

	// Stale clone for peer2 arrives while all three fresh entries exist.
	stale2 := llgrMultipathPath(t, peer2, "10.10.0.0/24", "192.0.2.2", true)
	manager.Update(stale2)

	// A withdrawal from a source that never installed a path (e.g. a
	// retransmitted or duplicated withdraw) must be a no-op rather than
	// disturbing the multipath set.
	dupe := llgrMultipathPath(t, llgrTestPeer("10.0.9.9"), "10.10.0.0/24", "192.0.2.9", true)
	dupe.IsWithdraw = true
	assert.Empty(t, manager.Update(dupe))

	// Withdraw peer1's fresh path first, then peer3's: after the first
	// withdrawal peer3 is still fresh, so the stale path must not sneak in.
	dsts := manager.Update(p1.Clone(true))
	require.Len(t, dsts, 1)
	mp := getMultiBestPath(GLOBAL_RIB_NAME, dsts[0].KnownPathList)
	require.Len(t, mp, 1)
	assert.Equal(t, "192.0.2.3", mp[0].GetNexthop().String())

	// Last fresh path gone: only the stale candidate remains, and LLGR
	// degradation says it is still the best/multipath path.
	dsts = manager.Update(p3.Clone(true))
	require.Len(t, dsts, 1)
	mp = getMultiBestPath(GLOBAL_RIB_NAME, dsts[0].KnownPathList)
	require.Len(t, mp, 1)
	assert.True(t, mp[0].IsLLGRStale())
	assert.Equal(t, "192.0.2.2", mp[0].GetNexthop().String())

	// The stale path's own withdrawal then empties the destination without
	// ever having produced a phantom fresh nexthop.
	dsts = manager.Update(stale2.Clone(true))
	require.Len(t, dsts, 1)
	assert.Empty(t, getMultiBestPath(GLOBAL_RIB_NAME, dsts[0].KnownPathList))
}
