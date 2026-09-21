package table

import (
	"net/netip"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func createPathWithCommunities(communities []uint32) *Path {
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	nlri, _ := bgp.NewIPAddrPrefix(prefix)
	nextHop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	attributes := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nextHop,
		bgp.NewPathAttributeCommunities(communities),
	}
	return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attributes, time.Now(), false)
}

func createPathWithExtCommunities(communities []bgp.ExtendedCommunityInterface) *Path {
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	nlri, _ := bgp.NewIPAddrPrefix(prefix)
	nextHop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	attributes := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nextHop,
		bgp.NewPathAttributeExtendedCommunities(communities),
	}
	return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attributes, time.Now(), false)
}
