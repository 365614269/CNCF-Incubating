// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api_v1alpha3.proto

/*
Package v1alpha3 is a generated protocol buffer package.

It is generated from these files:

	api_v1alpha3.proto

It has these top-level messages:

	OnDefineDomainParams
	OnDefineDomainResult
	PreCloudInitIsoParams
	PreCloudInitIsoResult
	ShutdownParams
	ShutdownResult
*/
package v1alpha3

import (
	fmt "fmt"

	proto "github.com/golang/protobuf/proto"

	math "math"

	context "golang.org/x/net/context"

	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type OnDefineDomainParams struct {
	// domainXML is original libvirt domain specification
	DomainXML []byte `protobuf:"bytes,1,opt,name=domainXML,proto3" json:"domainXML,omitempty"`
	// vmi is VirtualMachineInstance is object of virtual machine currently processed by virt-launcher, it is encoded as JSON
	Vmi []byte `protobuf:"bytes,2,opt,name=vmi,proto3" json:"vmi,omitempty"`
}

func (m *OnDefineDomainParams) Reset()                    { *m = OnDefineDomainParams{} }
func (m *OnDefineDomainParams) String() string            { return proto.CompactTextString(m) }
func (*OnDefineDomainParams) ProtoMessage()               {}
func (*OnDefineDomainParams) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *OnDefineDomainParams) GetDomainXML() []byte {
	if m != nil {
		return m.DomainXML
	}
	return nil
}

func (m *OnDefineDomainParams) GetVmi() []byte {
	if m != nil {
		return m.Vmi
	}
	return nil
}

type OnDefineDomainResult struct {
	// domainXML is processed libvirt domain specification
	DomainXML []byte `protobuf:"bytes,1,opt,name=domainXML,proto3" json:"domainXML,omitempty"`
}

func (m *OnDefineDomainResult) Reset()                    { *m = OnDefineDomainResult{} }
func (m *OnDefineDomainResult) String() string            { return proto.CompactTextString(m) }
func (*OnDefineDomainResult) ProtoMessage()               {}
func (*OnDefineDomainResult) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *OnDefineDomainResult) GetDomainXML() []byte {
	if m != nil {
		return m.DomainXML
	}
	return nil
}

type PreCloudInitIsoParams struct {
	// cloudInitNoCloudSource is an object of CloudInitNoCloudSource encoded as JSON
	// This is a legacy field to ensure backwards compatibility. New code should use cloudInitData instead.
	CloudInitNoCloudSource []byte `protobuf:"bytes,1,opt,name=cloudInitNoCloudSource,proto3" json:"cloudInitNoCloudSource,omitempty"`
	// vmi is VirtualMachineInstance is object of virtual machine currently processed by virt-launcher, it is encoded as JSON
	Vmi []byte `protobuf:"bytes,2,opt,name=vmi,proto3" json:"vmi,omitempty"`
	// cloudInitData is an object of CloudInitData encoded as JSON
	CloudInitData []byte `protobuf:"bytes,3,opt,name=cloudInitData,proto3" json:"cloudInitData,omitempty"`
}

func (m *PreCloudInitIsoParams) Reset()                    { *m = PreCloudInitIsoParams{} }
func (m *PreCloudInitIsoParams) String() string            { return proto.CompactTextString(m) }
func (*PreCloudInitIsoParams) ProtoMessage()               {}
func (*PreCloudInitIsoParams) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *PreCloudInitIsoParams) GetCloudInitNoCloudSource() []byte {
	if m != nil {
		return m.CloudInitNoCloudSource
	}
	return nil
}

func (m *PreCloudInitIsoParams) GetVmi() []byte {
	if m != nil {
		return m.Vmi
	}
	return nil
}

func (m *PreCloudInitIsoParams) GetCloudInitData() []byte {
	if m != nil {
		return m.CloudInitData
	}
	return nil
}

type PreCloudInitIsoResult struct {
	// cloudInitNoCloudSource is an object of CloudInitNoCloudSource encoded as JSON
	// This is a legacy field to ensure backwards compatibility. New code should use cloudInitData instead.
	CloudInitNoCloudSource []byte `protobuf:"bytes,1,opt,name=cloudInitNoCloudSource,proto3" json:"cloudInitNoCloudSource,omitempty"`
	// cloudInitData is an object of CloudInitData encoded as JSON
	CloudInitData []byte `protobuf:"bytes,3,opt,name=cloudInitData,proto3" json:"cloudInitData,omitempty"`
}

func (m *PreCloudInitIsoResult) Reset()                    { *m = PreCloudInitIsoResult{} }
func (m *PreCloudInitIsoResult) String() string            { return proto.CompactTextString(m) }
func (*PreCloudInitIsoResult) ProtoMessage()               {}
func (*PreCloudInitIsoResult) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *PreCloudInitIsoResult) GetCloudInitNoCloudSource() []byte {
	if m != nil {
		return m.CloudInitNoCloudSource
	}
	return nil
}

func (m *PreCloudInitIsoResult) GetCloudInitData() []byte {
	if m != nil {
		return m.CloudInitData
	}
	return nil
}

type ShutdownParams struct {
}

func (m *ShutdownParams) Reset()                    { *m = ShutdownParams{} }
func (m *ShutdownParams) String() string            { return proto.CompactTextString(m) }
func (*ShutdownParams) ProtoMessage()               {}
func (*ShutdownParams) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

type ShutdownResult struct {
}

func (m *ShutdownResult) Reset()                    { *m = ShutdownResult{} }
func (m *ShutdownResult) String() string            { return proto.CompactTextString(m) }
func (*ShutdownResult) ProtoMessage()               {}
func (*ShutdownResult) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func init() {
	proto.RegisterType((*OnDefineDomainParams)(nil), "kubevirt.hooks.v1alpha3.OnDefineDomainParams")
	proto.RegisterType((*OnDefineDomainResult)(nil), "kubevirt.hooks.v1alpha3.OnDefineDomainResult")
	proto.RegisterType((*PreCloudInitIsoParams)(nil), "kubevirt.hooks.v1alpha3.PreCloudInitIsoParams")
	proto.RegisterType((*PreCloudInitIsoResult)(nil), "kubevirt.hooks.v1alpha3.PreCloudInitIsoResult")
	proto.RegisterType((*ShutdownParams)(nil), "kubevirt.hooks.v1alpha3.ShutdownParams")
	proto.RegisterType((*ShutdownResult)(nil), "kubevirt.hooks.v1alpha3.ShutdownResult")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Callbacks service

type CallbacksClient interface {
	OnDefineDomain(ctx context.Context, in *OnDefineDomainParams, opts ...grpc.CallOption) (*OnDefineDomainResult, error)
	PreCloudInitIso(ctx context.Context, in *PreCloudInitIsoParams, opts ...grpc.CallOption) (*PreCloudInitIsoResult, error)
	Shutdown(ctx context.Context, in *ShutdownParams, opts ...grpc.CallOption) (*ShutdownResult, error)
}

type callbacksClient struct {
	cc *grpc.ClientConn
}

func NewCallbacksClient(cc *grpc.ClientConn) CallbacksClient {
	return &callbacksClient{cc}
}

func (c *callbacksClient) OnDefineDomain(ctx context.Context, in *OnDefineDomainParams, opts ...grpc.CallOption) (*OnDefineDomainResult, error) {
	out := new(OnDefineDomainResult)
	err := grpc.Invoke(ctx, "/kubevirt.hooks.v1alpha3.Callbacks/OnDefineDomain", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *callbacksClient) PreCloudInitIso(ctx context.Context, in *PreCloudInitIsoParams, opts ...grpc.CallOption) (*PreCloudInitIsoResult, error) {
	out := new(PreCloudInitIsoResult)
	err := grpc.Invoke(ctx, "/kubevirt.hooks.v1alpha3.Callbacks/PreCloudInitIso", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *callbacksClient) Shutdown(ctx context.Context, in *ShutdownParams, opts ...grpc.CallOption) (*ShutdownResult, error) {
	out := new(ShutdownResult)
	err := grpc.Invoke(ctx, "/kubevirt.hooks.v1alpha3.Callbacks/Shutdown", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Callbacks service

type CallbacksServer interface {
	OnDefineDomain(context.Context, *OnDefineDomainParams) (*OnDefineDomainResult, error)
	PreCloudInitIso(context.Context, *PreCloudInitIsoParams) (*PreCloudInitIsoResult, error)
	Shutdown(context.Context, *ShutdownParams) (*ShutdownResult, error)
}

func RegisterCallbacksServer(s *grpc.Server, srv CallbacksServer) {
	s.RegisterService(&_Callbacks_serviceDesc, srv)
}

func _Callbacks_OnDefineDomain_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(OnDefineDomainParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CallbacksServer).OnDefineDomain(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kubevirt.hooks.v1alpha3.Callbacks/OnDefineDomain",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CallbacksServer).OnDefineDomain(ctx, req.(*OnDefineDomainParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _Callbacks_PreCloudInitIso_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PreCloudInitIsoParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CallbacksServer).PreCloudInitIso(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kubevirt.hooks.v1alpha3.Callbacks/PreCloudInitIso",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CallbacksServer).PreCloudInitIso(ctx, req.(*PreCloudInitIsoParams))
	}
	return interceptor(ctx, in, info, handler)
}

func _Callbacks_Shutdown_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ShutdownParams)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CallbacksServer).Shutdown(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kubevirt.hooks.v1alpha3.Callbacks/Shutdown",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CallbacksServer).Shutdown(ctx, req.(*ShutdownParams))
	}
	return interceptor(ctx, in, info, handler)
}

var _Callbacks_serviceDesc = grpc.ServiceDesc{
	ServiceName: "kubevirt.hooks.v1alpha3.Callbacks",
	HandlerType: (*CallbacksServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "OnDefineDomain",
			Handler:    _Callbacks_OnDefineDomain_Handler,
		},
		{
			MethodName: "PreCloudInitIso",
			Handler:    _Callbacks_PreCloudInitIso_Handler,
		},
		{
			MethodName: "Shutdown",
			Handler:    _Callbacks_Shutdown_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api_v1alpha3.proto",
}

func init() { proto.RegisterFile("api_v1alpha3.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 296 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0x4a, 0x2c, 0xc8, 0x8c,
	0x2f, 0x33, 0x4c, 0xcc, 0x29, 0xc8, 0x48, 0x34, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x12,
	0xcf, 0x2e, 0x4d, 0x4a, 0x2d, 0xcb, 0x2c, 0x2a, 0xd1, 0xcb, 0xc8, 0xcf, 0xcf, 0x2e, 0xd6, 0x83,
	0x49, 0x2b, 0xb9, 0x71, 0x89, 0xf8, 0xe7, 0xb9, 0xa4, 0xa6, 0x65, 0xe6, 0xa5, 0xba, 0xe4, 0xe7,
	0x26, 0x66, 0xe6, 0x05, 0x24, 0x16, 0x25, 0xe6, 0x16, 0x0b, 0xc9, 0x70, 0x71, 0xa6, 0x80, 0xf9,
	0x11, 0xbe, 0x3e, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0x3c, 0x41, 0x08, 0x01, 0x21, 0x01, 0x2e, 0xe6,
	0xb2, 0xdc, 0x4c, 0x09, 0x26, 0xb0, 0x38, 0x88, 0xa9, 0x64, 0x82, 0x6e, 0x4e, 0x50, 0x6a, 0x71,
	0x69, 0x4e, 0x09, 0x7e, 0x73, 0x94, 0xda, 0x19, 0xb9, 0x44, 0x03, 0x8a, 0x52, 0x9d, 0x73, 0xf2,
	0x4b, 0x53, 0x3c, 0xf3, 0x32, 0x4b, 0x3c, 0x8b, 0xf3, 0xa1, 0xf6, 0x9b, 0x71, 0x89, 0x25, 0xc3,
	0x44, 0xfd, 0xf2, 0xc1, 0x0a, 0x82, 0xf3, 0x4b, 0x8b, 0x92, 0x53, 0xa1, 0x86, 0xe0, 0x90, 0xc5,
	0x74, 0x99, 0x90, 0x0a, 0x17, 0x2f, 0x5c, 0xad, 0x4b, 0x62, 0x49, 0xa2, 0x04, 0x33, 0x58, 0x0e,
	0x55, 0x50, 0xa9, 0x14, 0xc3, 0x21, 0x50, 0x0f, 0x90, 0xeb, 0x10, 0xe2, 0xac, 0x15, 0xe0, 0xe2,
	0x0b, 0xce, 0x28, 0x2d, 0x49, 0xc9, 0x2f, 0x87, 0x06, 0x3c, 0xb2, 0x08, 0xc4, 0x05, 0x46, 0x67,
	0x98, 0xb8, 0x38, 0x9d, 0x13, 0x73, 0x72, 0x92, 0x12, 0x93, 0xb3, 0x8b, 0x85, 0xf2, 0xb8, 0xf8,
	0x50, 0x03, 0x5a, 0x48, 0x57, 0x0f, 0x47, 0xe4, 0xea, 0x61, 0x8b, 0x59, 0x29, 0x62, 0x95, 0x43,
	0xfd, 0x5f, 0xc8, 0xc5, 0x8f, 0x16, 0x30, 0x42, 0x7a, 0x38, 0x4d, 0xc0, 0x1a, 0x97, 0x52, 0x44,
	0xab, 0x87, 0x5a, 0x19, 0xc3, 0xc5, 0x01, 0x0b, 0x02, 0x21, 0x75, 0x9c, 0x7a, 0x51, 0xc3, 0x4d,
	0x8a, 0xb0, 0x42, 0x88, 0xe9, 0x49, 0x6c, 0xe0, 0x1c, 0x61, 0x0c, 0x08, 0x00, 0x00, 0xff, 0xff,
	0x99, 0x7e, 0x92, 0xc5, 0x27, 0x03, 0x00, 0x00,
}
