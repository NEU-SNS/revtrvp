package client

import (
	"github.com/NEU-SNS/revtrvp/controller/pb"
	"github.com/NEU-SNS/revtrvp/datamodel"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type client struct {
	context.Context
	controllerapi.ControllerClient
}

// Client is a client for the controller
type Client interface {
	Ping(context.Context, *datamodel.PingArg) (controllerapi.Controller_PingClient, error)
	Traceroute(context.Context, *datamodel.TracerouteArg) (controllerapi.Controller_TracerouteClient, error)
	GetVps(context.Context, *datamodel.VPRequest) (*datamodel.VPReturn, error)
	ReceiveSpoofedProbes(context.Context) (controllerapi.Controller_ReceiveSpoofedProbesClient, error)
}

// New creates a new controller client
func New(ctx context.Context, cc *grpc.ClientConn) Client {
	return client{Context: ctx, ControllerClient: controllerapi.NewControllerClient(cc)}
}

func (c client) Ping(ctx context.Context, pa *datamodel.PingArg) (controllerapi.Controller_PingClient, error) {
	return c.ControllerClient.Ping(ctx, pa)
}

func (c client) Traceroute(ctx context.Context, ta *datamodel.TracerouteArg) (controllerapi.Controller_TracerouteClient, error) {
	return c.ControllerClient.Traceroute(ctx, ta)
}

func (c client) GetVps(ctx context.Context, vpr *datamodel.VPRequest) (*datamodel.VPReturn, error) {
	return c.ControllerClient.GetVPs(ctx, vpr)
}

func (c client) ReceiveSpoofedProbes(ctx context.Context) (controllerapi.Controller_ReceiveSpoofedProbesClient, error) {
	return c.ControllerClient.ReceiveSpoofedProbes(ctx)
}
