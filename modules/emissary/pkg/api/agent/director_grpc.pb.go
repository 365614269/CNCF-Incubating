//*
// Communication between the Ambassador Agent and the Director service
// to populate the Central Edge Policy Console, which is a cloud service
// run by Datawire.

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v3.21.5
// source: agent/director.proto

package agent

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	Director_Report_FullMethodName              = "/agent.Director/Report"
	Director_ReportStream_FullMethodName        = "/agent.Director/ReportStream"
	Director_StreamDiagnostics_FullMethodName   = "/agent.Director/StreamDiagnostics"
	Director_StreamMetrics_FullMethodName       = "/agent.Director/StreamMetrics"
	Director_Retrieve_FullMethodName            = "/agent.Director/Retrieve"
	Director_ReportCommandResult_FullMethodName = "/agent.Director/ReportCommandResult"
)

// DirectorClient is the client API for Director service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type DirectorClient interface {
	// Deprecated: Do not use.
	// Report a consistent Snapshot of information to the DCP.  This
	// method is deprecated, you should call ReportStream instead.
	Report(ctx context.Context, in *Snapshot, opts ...grpc.CallOption) (*SnapshotResponse, error)
	// Report a consistent Snapshot of information to the DCP.
	ReportStream(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[RawSnapshotChunk, SnapshotResponse], error)
	// Report a consistent Diagnostics snapshot of information to the DCP.
	StreamDiagnostics(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[RawDiagnosticsChunk, DiagnosticsResponse], error)
	// Stream metrics to the DCP.
	StreamMetrics(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[StreamMetricsMessage, StreamMetricsResponse], error)
	// Retrieve Directives from the DCP
	Retrieve(ctx context.Context, in *Identity, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Directive], error)
	// Reports the result of a command execution to the cloud
	ReportCommandResult(ctx context.Context, in *CommandResult, opts ...grpc.CallOption) (*CommandResultResponse, error)
}

type directorClient struct {
	cc grpc.ClientConnInterface
}

func NewDirectorClient(cc grpc.ClientConnInterface) DirectorClient {
	return &directorClient{cc}
}

// Deprecated: Do not use.
func (c *directorClient) Report(ctx context.Context, in *Snapshot, opts ...grpc.CallOption) (*SnapshotResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SnapshotResponse)
	err := c.cc.Invoke(ctx, Director_Report_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *directorClient) ReportStream(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[RawSnapshotChunk, SnapshotResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Director_ServiceDesc.Streams[0], Director_ReportStream_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[RawSnapshotChunk, SnapshotResponse]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Director_ReportStreamClient = grpc.ClientStreamingClient[RawSnapshotChunk, SnapshotResponse]

func (c *directorClient) StreamDiagnostics(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[RawDiagnosticsChunk, DiagnosticsResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Director_ServiceDesc.Streams[1], Director_StreamDiagnostics_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[RawDiagnosticsChunk, DiagnosticsResponse]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Director_StreamDiagnosticsClient = grpc.ClientStreamingClient[RawDiagnosticsChunk, DiagnosticsResponse]

func (c *directorClient) StreamMetrics(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[StreamMetricsMessage, StreamMetricsResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Director_ServiceDesc.Streams[2], Director_StreamMetrics_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[StreamMetricsMessage, StreamMetricsResponse]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Director_StreamMetricsClient = grpc.ClientStreamingClient[StreamMetricsMessage, StreamMetricsResponse]

func (c *directorClient) Retrieve(ctx context.Context, in *Identity, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Directive], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Director_ServiceDesc.Streams[3], Director_Retrieve_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Identity, Directive]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Director_RetrieveClient = grpc.ServerStreamingClient[Directive]

func (c *directorClient) ReportCommandResult(ctx context.Context, in *CommandResult, opts ...grpc.CallOption) (*CommandResultResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CommandResultResponse)
	err := c.cc.Invoke(ctx, Director_ReportCommandResult_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DirectorServer is the server API for Director service.
// All implementations must embed UnimplementedDirectorServer
// for forward compatibility.
type DirectorServer interface {
	// Deprecated: Do not use.
	// Report a consistent Snapshot of information to the DCP.  This
	// method is deprecated, you should call ReportStream instead.
	Report(context.Context, *Snapshot) (*SnapshotResponse, error)
	// Report a consistent Snapshot of information to the DCP.
	ReportStream(grpc.ClientStreamingServer[RawSnapshotChunk, SnapshotResponse]) error
	// Report a consistent Diagnostics snapshot of information to the DCP.
	StreamDiagnostics(grpc.ClientStreamingServer[RawDiagnosticsChunk, DiagnosticsResponse]) error
	// Stream metrics to the DCP.
	StreamMetrics(grpc.ClientStreamingServer[StreamMetricsMessage, StreamMetricsResponse]) error
	// Retrieve Directives from the DCP
	Retrieve(*Identity, grpc.ServerStreamingServer[Directive]) error
	// Reports the result of a command execution to the cloud
	ReportCommandResult(context.Context, *CommandResult) (*CommandResultResponse, error)
	mustEmbedUnimplementedDirectorServer()
}

// UnimplementedDirectorServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedDirectorServer struct{}

func (UnimplementedDirectorServer) Report(context.Context, *Snapshot) (*SnapshotResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Report not implemented")
}
func (UnimplementedDirectorServer) ReportStream(grpc.ClientStreamingServer[RawSnapshotChunk, SnapshotResponse]) error {
	return status.Errorf(codes.Unimplemented, "method ReportStream not implemented")
}
func (UnimplementedDirectorServer) StreamDiagnostics(grpc.ClientStreamingServer[RawDiagnosticsChunk, DiagnosticsResponse]) error {
	return status.Errorf(codes.Unimplemented, "method StreamDiagnostics not implemented")
}
func (UnimplementedDirectorServer) StreamMetrics(grpc.ClientStreamingServer[StreamMetricsMessage, StreamMetricsResponse]) error {
	return status.Errorf(codes.Unimplemented, "method StreamMetrics not implemented")
}
func (UnimplementedDirectorServer) Retrieve(*Identity, grpc.ServerStreamingServer[Directive]) error {
	return status.Errorf(codes.Unimplemented, "method Retrieve not implemented")
}
func (UnimplementedDirectorServer) ReportCommandResult(context.Context, *CommandResult) (*CommandResultResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReportCommandResult not implemented")
}
func (UnimplementedDirectorServer) mustEmbedUnimplementedDirectorServer() {}
func (UnimplementedDirectorServer) testEmbeddedByValue()                  {}

// UnsafeDirectorServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to DirectorServer will
// result in compilation errors.
type UnsafeDirectorServer interface {
	mustEmbedUnimplementedDirectorServer()
}

func RegisterDirectorServer(s grpc.ServiceRegistrar, srv DirectorServer) {
	// If the following call pancis, it indicates UnimplementedDirectorServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Director_ServiceDesc, srv)
}

func _Director_Report_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Snapshot)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DirectorServer).Report(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Director_Report_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DirectorServer).Report(ctx, req.(*Snapshot))
	}
	return interceptor(ctx, in, info, handler)
}

func _Director_ReportStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DirectorServer).ReportStream(&grpc.GenericServerStream[RawSnapshotChunk, SnapshotResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Director_ReportStreamServer = grpc.ClientStreamingServer[RawSnapshotChunk, SnapshotResponse]

func _Director_StreamDiagnostics_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DirectorServer).StreamDiagnostics(&grpc.GenericServerStream[RawDiagnosticsChunk, DiagnosticsResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Director_StreamDiagnosticsServer = grpc.ClientStreamingServer[RawDiagnosticsChunk, DiagnosticsResponse]

func _Director_StreamMetrics_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DirectorServer).StreamMetrics(&grpc.GenericServerStream[StreamMetricsMessage, StreamMetricsResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Director_StreamMetricsServer = grpc.ClientStreamingServer[StreamMetricsMessage, StreamMetricsResponse]

func _Director_Retrieve_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Identity)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(DirectorServer).Retrieve(m, &grpc.GenericServerStream[Identity, Directive]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Director_RetrieveServer = grpc.ServerStreamingServer[Directive]

func _Director_ReportCommandResult_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CommandResult)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DirectorServer).ReportCommandResult(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Director_ReportCommandResult_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DirectorServer).ReportCommandResult(ctx, req.(*CommandResult))
	}
	return interceptor(ctx, in, info, handler)
}

// Director_ServiceDesc is the grpc.ServiceDesc for Director service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Director_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "agent.Director",
	HandlerType: (*DirectorServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Report",
			Handler:    _Director_Report_Handler,
		},
		{
			MethodName: "ReportCommandResult",
			Handler:    _Director_ReportCommandResult_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ReportStream",
			Handler:       _Director_ReportStream_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "StreamDiagnostics",
			Handler:       _Director_StreamDiagnostics_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "StreamMetrics",
			Handler:       _Director_StreamMetrics_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "Retrieve",
			Handler:       _Director_Retrieve_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "agent/director.proto",
}
