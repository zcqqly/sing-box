//go:build with_gvisor

package tun

import (
	"context"
	"net/netip"
	"time"
	"unsafe"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
)

// NB4A: mirror of sing-tun GVisor struct layout (up to `endpoint`).
// fixGvisorClose() reinterprets *tun.GVisor as this type via unsafe.Pointer,
// so the field order and types MUST match sing-tun exactly.
// Updated for sing-tun v0.9.7 (sing-box 1.14.4): new fields inet4Address,
// inet6Address, icmpTimeout and udpNATOptions were added before `stack`.
type gVisor struct {
	ctx                  context.Context
	tun                  tun.GVisorTun
	inet4Address         netip.Addr
	inet6Address         netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	icmpTimeout          time.Duration
	udpNATOptions        tun.UDPNatOptions
	broadcastAddr        netip.Addr
	handler              tun.Handler
	logger               logger.Logger
	stack                *stack.Stack
	endpoint             stack.LinkEndpoint
}

func (t *gVisor) Close() error {
	if t.stack == nil {
		return nil
	}
	t.endpoint.(*tun.LinkEndpointFilter).LinkEndpoint.Attach(nil)
	t.stack.Close()
	for _, endpoint := range t.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	return nil
}

func (t *Inbound) fixGvisorClose() {
	// 正确的修复方式：修改 sing-tun 里面的 func (w *LinkEndpointFilter) Attach
	if gvs, ok := t.tunStack.(*tun.GVisor); ok {
		p := (*gVisor)(unsafe.Pointer(gvs))
		p.Close()
		p.stack = nil // prevent next Close
	}
}
