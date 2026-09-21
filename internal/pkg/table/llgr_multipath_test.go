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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// mkLLGRTestPath builds an eBGP-learned path for 10.0.0.0/24 whose only
// varying attribute across callers is the peer and the communities.
// LOCAL_PREF / AS_PATH length / ORIGIN / MED are identical, so Path.Compare
// treats every two such paths as equivalent multipath candidates.
func mkLLGRTestPath(t *testing.T, asn uint32, addr, nexthop string, stale bool) *Path {
	t.Helper()
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.0.0.0/24"))
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65100}),
		}),
		nh,
	}
	p := NewPath(bgp.RF_IPv4_UC, &PeerInfo{AS: asn, Address: netip.MustParseAddr(addr)},
		bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
	if stale {
		p.SetCommunities([]uint32{uint32(bgp.COMMUNITY_LLGR_STALE)}, false)
	}
	return p
}

func llgrTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// Regression for the live-cutover incident: a fresh path and an LLGR_STALE
// path for the same prefix must never be equivalent multipath candidates.
// Before the fix getMultiBestPath used Path.Compare, which ignores the
// LLGR_STALE community, and installed the dead campus egress next to the
// fresh path.
func TestGetMultiBestPath_FreshPathNotMultipathWithLLGRStale(t *testing.T) {
	fresh := mkLLGRTestPath(t, 65001, "192.0.2.1", "192.0.2.1", false)
	stale := mkLLGRTestPath(t, 65002, "198.51.100.1", "198.51.100.1", true)

	// The two paths share every Compare() attribute except the community;
	// Compare must still rank the fresh path strictly above the stale one,
	// otherwise they would be treated as equivalent multipath candidates.
	assert.Positive(t, fresh.Compare(stale))
	assert.Negative(t, stale.Compare(fresh))
	assert.True(t, fresh.IsLLGRStale() != stale.IsLLGRStale())

	// insertSort must rank the fresh path ahead of the stale one.
	d := newDestination(fresh.GetNlri(), 0)
	for _, p := range []*Path{stale, fresh} {
		d.Calculate(llgrTestLogger(), p, oc.RouteSelectionOptionsConfig{})
	}

	mp := d.GetMultiBestPath(GLOBAL_RIB_NAME)
	require.Len(t, mp, 1, "stale path must not join multipath while a fresh path exists")
	assert.Same(t, fresh, mp[0])

	// Best path must be the fresh one even though the stale path arrived first.
	assert.Same(t, fresh, d.GetBestPath(GLOBAL_RIB_NAME, 0))
}

// When every retained path is LLGR_STALE the speaker has no fresh
// alternative: RFC 9494 degradation semantics say the stale paths stay in
// use (deprioritized against any future fresh path, but still forwarded).
func TestGetMultiBestPath_AllLLGRStaleKeepsDegradedMultipath(t *testing.T) {
	stale1 := mkLLGRTestPath(t, 65001, "192.0.2.1", "192.0.2.1", true)
	stale2 := mkLLGRTestPath(t, 65002, "198.51.100.1", "198.51.100.1", true)

	d := newDestination(stale1.GetNlri(), 0, stale1, stale2)
	mp := d.GetMultiBestPath(GLOBAL_RIB_NAME)
	require.Len(t, mp, 2, "all-stale paths retain the LLGR degraded multipath semantics")
}

// A fresh path appearing next to two stale paths must collapse multipath to
// itself; both stale entries have to be withdrawn from the forwarding plane.
func TestGetMultiBestPathDiff_FreshPathReplacesStaleMultipath(t *testing.T) {
	stale1 := mkLLGRTestPath(t, 65001, "192.0.2.1", "192.0.2.1", true)
	stale2 := mkLLGRTestPath(t, 65002, "198.51.100.1", "198.51.100.1", true)
	fresh := mkLLGRTestPath(t, 65003, "203.0.113.1", "203.0.113.1", false)

	u := &Update{
		OldKnownPathList: []*Path{stale1, stale2},
		KnownPathList:    []*Path{fresh, stale1, stale2},
	}
	updates, withdraws := u.GetMultiBestPathDiff(GLOBAL_RIB_NAME)
	require.Len(t, updates, 1)
	assert.Same(t, fresh, updates[0])
	require.Len(t, withdraws, 2, "both stale next hops must be withdrawn when a fresh path arrives")
	for _, w := range withdraws {
		assert.True(t, w.IsWithdraw)
		assert.True(t, w.IsLLGRStale())
	}
}

// Marking the only remaining paths LLGR_STALE (session reset with LLGR) must
// not churn multipath: the stale paths stay installed as degraded forwarding
// entries, producing no spurious withdraws.
func TestGetMultiBestPathDiff_AllGoStaleIsNoop(t *testing.T) {
	p1 := mkLLGRTestPath(t, 65001, "192.0.2.1", "192.0.2.1", true)
	p2 := mkLLGRTestPath(t, 65002, "198.51.100.1", "198.51.100.1", true)

	u := &Update{
		OldKnownPathList: []*Path{p1, p2},
		KnownPathList:    []*Path{p1, p2},
	}
	updates, withdraws := u.GetMultiBestPathDiff(GLOBAL_RIB_NAME)
	assert.Empty(t, updates)
	assert.Empty(t, withdraws, "entering LLGR with all paths stale must not generate withdraws")
}

// GetChanges (used by propagateUpdateToNeighbors) must report only the fresh
// path as the multipath set; it drives notifyBestWatcher and hence the
// zclient FIB installation.
func TestGetChanges_MultipathExcludesStaleWhenFreshExists(t *testing.T) {
	fresh := mkLLGRTestPath(t, 65001, "192.0.2.1", "192.0.2.1", false)
	stale := mkLLGRTestPath(t, 65002, "198.51.100.1", "198.51.100.1", true)

	u := &Update{
		OldKnownPathList: []*Path{stale},
		KnownPathList:    []*Path{fresh, stale},
	}
	best, _, multi := u.GetChanges(GLOBAL_RIB_NAME, 0, false, true)
	require.NotNil(t, best)
	assert.Same(t, fresh, best)
	require.Len(t, multi, 1, "multipath delta must contain only the fresh path")
	assert.Same(t, fresh, multi[0])
}

// Select with Best+MultiPath (CLI / API path) must not flag the stale path
// as best while a fresh path exists.
func TestSelect_BestMultiPathExcludesLLGRStale(t *testing.T) {
	fresh := mkLLGRTestPath(t, 65001, "192.0.2.1", "192.0.2.1", false)
	stale := mkLLGRTestPath(t, 65002, "198.51.100.1", "198.51.100.1", true)

	d := newDestination(fresh.GetNlri(), 0, fresh, stale)
	selected := d.Select(DestinationSelectOption{ID: GLOBAL_RIB_NAME, Best: true, MultiPath: true})
	require.NotNil(t, selected)
	assert.Len(t, selected.GetAllKnownPathList(), 1)
}

// Out-of-order withdrawal scenario: the fresh path is withdrawn first while
// the stale path is retained. Multipath must fall back to the stale path
// (LLGR degradation), and when the stale path is withdrawn afterwards the
// destination empties.
func TestCalculate_OutofOrderWithdrawFallsBackToStale(t *testing.T) {
	logger := llgrTestLogger()
	fresh := mkLLGRTestPath(t, 65001, "192.0.2.1", "192.0.2.1", false)
	stale := mkLLGRTestPath(t, 65002, "198.51.100.1", "198.51.100.1", true)

	d := newDestination(fresh.GetNlri(), 0)
	for _, p := range []*Path{stale, fresh} {
		d.Calculate(logger, p, oc.RouteSelectionOptionsConfig{})
	}
	require.Len(t, d.GetMultiBestPath(GLOBAL_RIB_NAME), 1)

	// Withdraw the fresh path out of order: multipath must withdraw the
	// fresh next hop and fall back to the retained stale path (LLGR
	// degradation), rather than declaring the destination dead.
	wFresh := fresh.Clone(true)
	u, _ := d.Calculate(logger, wFresh, oc.RouteSelectionOptionsConfig{})
	updates, withdraws := u.GetMultiBestPathDiff(GLOBAL_RIB_NAME)
	require.Len(t, withdraws, 1, "the fresh next hop is withdrawn")
	assert.False(t, withdraws[0].IsLLGRStale())
	require.Len(t, updates, 1, "stale path takes over as degraded best")
	assert.True(t, updates[0].IsLLGRStale())
	assert.Len(t, d.GetMultiBestPath(GLOBAL_RIB_NAME), 1)

	// Now the stale path is withdrawn: destination empties.
	wStale := stale.Clone(true)
	u, _ = d.Calculate(logger, wStale, oc.RouteSelectionOptionsConfig{})
	updates, withdraws = u.GetMultiBestPathDiff(GLOBAL_RIB_NAME)
	assert.Empty(t, updates)
	require.Len(t, withdraws, 1)
	assert.Empty(t, d.GetMultiBestPath(GLOBAL_RIB_NAME))
}
