// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v5.26.1
// source: envoy/service/discovery/v2/sds.proto

package discoveryv2

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "github.com/emissary-ingress/emissary/v3/pkg/api/envoy/annotations"
	v2 "github.com/emissary-ingress/emissary/v3/pkg/api/envoy/api/v2"
	_ "google.golang.org/genproto/googleapis/api/annotations"
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

// [#not-implemented-hide:] Not configuration. Workaround c++ protobuf issue with importing
// services: https://github.com/google/protobuf/issues/4221
type SdsDummy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SdsDummy) Reset() {
	*x = SdsDummy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_service_discovery_v2_sds_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SdsDummy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SdsDummy) ProtoMessage() {}

func (x *SdsDummy) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_service_discovery_v2_sds_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SdsDummy.ProtoReflect.Descriptor instead.
func (*SdsDummy) Descriptor() ([]byte, []int) {
	return file_envoy_service_discovery_v2_sds_proto_rawDescGZIP(), []int{0}
}

var File_envoy_service_discovery_v2_sds_proto protoreflect.FileDescriptor

var file_envoy_service_discovery_v2_sds_proto_rawDesc = []byte{
	0x0a, 0x24, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2f,
	0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x76, 0x32, 0x2f, 0x73, 0x64, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e,
	0x76, 0x32, 0x1a, 0x1c, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x32,
	0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1e, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x6d, 0x69, 0x67, 0x72, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x0a, 0x0a, 0x08, 0x53, 0x64, 0x73, 0x44, 0x75, 0x6d, 0x6d, 0x79, 0x32, 0xe6, 0x02, 0x0a, 0x16,
	0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x5f, 0x0a, 0x0c, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x53,
	0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x12, 0x23, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x44, 0x69, 0x73, 0x63, 0x6f,
	0x76, 0x65, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x44, 0x65, 0x6c, 0x74, 0x61,
	0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x00, 0x28, 0x01, 0x30, 0x01, 0x12, 0x56, 0x0a, 0x0d, 0x53, 0x74, 0x72, 0x65, 0x61,
	0x6d, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x12, 0x1e, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72,
	0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72,
	0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x28, 0x01, 0x30, 0x01, 0x12,
	0x71, 0x0a, 0x0c, 0x46, 0x65, 0x74, 0x63, 0x68, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x12,
	0x1e, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x44,
	0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x1f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x44,
	0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x20, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1a, 0x3a, 0x01, 0x2a, 0x22, 0x15, 0x2f, 0x76, 0x32,
	0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x3a, 0x73, 0x65, 0x63, 0x72, 0x65,
	0x74, 0x73, 0x1a, 0x20, 0x8a, 0xa4, 0x96, 0xf3, 0x07, 0x1a, 0x0a, 0x18, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x32, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x53, 0x65,
	0x63, 0x72, 0x65, 0x74, 0x42, 0xac, 0x01, 0xf2, 0x98, 0xfe, 0x8f, 0x05, 0x19, 0x12, 0x17, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x73, 0x65, 0x63,
	0x72, 0x65, 0x74, 0x2e, 0x76, 0x33, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x01, 0x0a, 0x28,
	0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x64, 0x69, 0x73, 0x63,
	0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x76, 0x32, 0x42, 0x08, 0x53, 0x64, 0x73, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x50, 0x01, 0x5a, 0x4d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f,
	0x76, 0x65, 0x72, 0x79, 0x2f, 0x76, 0x32, 0x3b, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72,
	0x79, 0x76, 0x32, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_service_discovery_v2_sds_proto_rawDescOnce sync.Once
	file_envoy_service_discovery_v2_sds_proto_rawDescData = file_envoy_service_discovery_v2_sds_proto_rawDesc
)

func file_envoy_service_discovery_v2_sds_proto_rawDescGZIP() []byte {
	file_envoy_service_discovery_v2_sds_proto_rawDescOnce.Do(func() {
		file_envoy_service_discovery_v2_sds_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_service_discovery_v2_sds_proto_rawDescData)
	})
	return file_envoy_service_discovery_v2_sds_proto_rawDescData
}

var file_envoy_service_discovery_v2_sds_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_service_discovery_v2_sds_proto_goTypes = []interface{}{
	(*SdsDummy)(nil),                  // 0: envoy.service.discovery.v2.SdsDummy
	(*v2.DeltaDiscoveryRequest)(nil),  // 1: envoy.api.v2.DeltaDiscoveryRequest
	(*v2.DiscoveryRequest)(nil),       // 2: envoy.api.v2.DiscoveryRequest
	(*v2.DeltaDiscoveryResponse)(nil), // 3: envoy.api.v2.DeltaDiscoveryResponse
	(*v2.DiscoveryResponse)(nil),      // 4: envoy.api.v2.DiscoveryResponse
}
var file_envoy_service_discovery_v2_sds_proto_depIdxs = []int32{
	1, // 0: envoy.service.discovery.v2.SecretDiscoveryService.DeltaSecrets:input_type -> envoy.api.v2.DeltaDiscoveryRequest
	2, // 1: envoy.service.discovery.v2.SecretDiscoveryService.StreamSecrets:input_type -> envoy.api.v2.DiscoveryRequest
	2, // 2: envoy.service.discovery.v2.SecretDiscoveryService.FetchSecrets:input_type -> envoy.api.v2.DiscoveryRequest
	3, // 3: envoy.service.discovery.v2.SecretDiscoveryService.DeltaSecrets:output_type -> envoy.api.v2.DeltaDiscoveryResponse
	4, // 4: envoy.service.discovery.v2.SecretDiscoveryService.StreamSecrets:output_type -> envoy.api.v2.DiscoveryResponse
	4, // 5: envoy.service.discovery.v2.SecretDiscoveryService.FetchSecrets:output_type -> envoy.api.v2.DiscoveryResponse
	3, // [3:6] is the sub-list for method output_type
	0, // [0:3] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_envoy_service_discovery_v2_sds_proto_init() }
func file_envoy_service_discovery_v2_sds_proto_init() {
	if File_envoy_service_discovery_v2_sds_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_service_discovery_v2_sds_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SdsDummy); i {
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
			RawDescriptor: file_envoy_service_discovery_v2_sds_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_envoy_service_discovery_v2_sds_proto_goTypes,
		DependencyIndexes: file_envoy_service_discovery_v2_sds_proto_depIdxs,
		MessageInfos:      file_envoy_service_discovery_v2_sds_proto_msgTypes,
	}.Build()
	File_envoy_service_discovery_v2_sds_proto = out.File
	file_envoy_service_discovery_v2_sds_proto_rawDesc = nil
	file_envoy_service_discovery_v2_sds_proto_goTypes = nil
	file_envoy_service_discovery_v2_sds_proto_depIdxs = nil
}
