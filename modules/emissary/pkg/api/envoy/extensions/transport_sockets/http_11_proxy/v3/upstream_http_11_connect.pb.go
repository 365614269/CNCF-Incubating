// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v5.26.1
// source: envoy/extensions/transport_sockets/http_11_proxy/v3/upstream_http_11_connect.proto

package http_11_proxyv3

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	v3 "github.com/emissary-ingress/emissary/v3/pkg/api/envoy/config/core/v3"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Configuration for HTTP/1.1 proxy transport sockets.
// This is intended for use in Envoy Mobile, though may eventually be extended
// for upstream Envoy use.
// If this transport socket is configured, and an intermediate filter adds the
// stream info necessary for proxying to the stream info (as the test filter
// does :repo:`here <test/integration/filters/header_to_proxy_filter.cc>`) then
//
//   - Upstream connections will be directed to the specified proxy address rather
//     than the host's address
//   - Upstream TLS connections will have a raw HTTP/1.1 CONNECT header prefaced
//     to the payload, and 200 response stripped (if less than 200 bytes)
//   - Plaintext HTTP/1.1 connections will be sent with a fully qualified URL.
//
// This transport socket is not compatible with HTTP/3, plaintext HTTP/2, or raw TCP.
type Http11ProxyUpstreamTransport struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The underlying transport socket being wrapped.
	TransportSocket *v3.TransportSocket `protobuf:"bytes,1,opt,name=transport_socket,json=transportSocket,proto3" json:"transport_socket,omitempty"`
}

func (x *Http11ProxyUpstreamTransport) Reset() {
	*x = Http11ProxyUpstreamTransport{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Http11ProxyUpstreamTransport) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Http11ProxyUpstreamTransport) ProtoMessage() {}

func (x *Http11ProxyUpstreamTransport) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Http11ProxyUpstreamTransport.ProtoReflect.Descriptor instead.
func (*Http11ProxyUpstreamTransport) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDescGZIP(), []int{0}
}

func (x *Http11ProxyUpstreamTransport) GetTransportSocket() *v3.TransportSocket {
	if x != nil {
		return x.TransportSocket
	}
	return nil
}

var File_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto protoreflect.FileDescriptor

var file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDesc = []byte{
	0x0a, 0x52, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x73, 0x6f, 0x63,
	0x6b, 0x65, 0x74, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x31, 0x31, 0x5f, 0x70, 0x72, 0x6f,
	0x78, 0x79, 0x2f, 0x76, 0x33, 0x2f, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f, 0x68,
	0x74, 0x74, 0x70, 0x5f, 0x31, 0x31, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x33, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74,
	0x5f, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x31, 0x31,
	0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x33, 0x1a, 0x1f, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x33, 0x2f,
	0x62, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61,
	0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64,
	0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x7a, 0x0a, 0x1c, 0x48, 0x74, 0x74, 0x70, 0x31, 0x31, 0x50, 0x72, 0x6f, 0x78,
	0x79, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f,
	0x72, 0x74, 0x12, 0x5a, 0x0a, 0x10, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x5f,
	0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65,
	0x2e, 0x76, 0x33, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x53, 0x6f, 0x63,
	0x6b, 0x65, 0x74, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01, 0x52, 0x0f, 0x74,
	0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x42, 0xd5,
	0x01, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0x0a, 0x41, 0x69, 0x6f, 0x2e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65,
	0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70,
	0x6f, 0x72, 0x74, 0x5f, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70,
	0x5f, 0x31, 0x31, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x33, 0x42, 0x1a, 0x55, 0x70,
	0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x48, 0x74, 0x74, 0x70, 0x31, 0x31, 0x43, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x6a, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61,
	0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x73, 0x6f,
	0x63, 0x6b, 0x65, 0x74, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x31, 0x31, 0x5f, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2f, 0x76, 0x33, 0x3b, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x31, 0x31, 0x5f, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x76, 0x33, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDescOnce sync.Once
	file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDescData = file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDesc
)

func file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDescGZIP() []byte {
	file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDescData)
	})
	return file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDescData
}

var file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_goTypes = []interface{}{
	(*Http11ProxyUpstreamTransport)(nil), // 0: envoy.extensions.transport_sockets.http_11_proxy.v3.Http11ProxyUpstreamTransport
	(*v3.TransportSocket)(nil),           // 1: envoy.config.core.v3.TransportSocket
}
var file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_depIdxs = []int32{
	1, // 0: envoy.extensions.transport_sockets.http_11_proxy.v3.Http11ProxyUpstreamTransport.transport_socket:type_name -> envoy.config.core.v3.TransportSocket
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() {
	file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_init()
}
func file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_init() {
	if File_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Http11ProxyUpstreamTransport); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_msgTypes,
	}.Build()
	File_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto = out.File
	file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_rawDesc = nil
	file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_goTypes = nil
	file_envoy_extensions_transport_sockets_http_11_proxy_v3_upstream_http_11_connect_proto_depIdxs = nil
}
