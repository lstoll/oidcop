// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.25.1
// source: storage.proto

package core

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// StoredToken represents the session-persisted state of a token
// we issued to a user
type StoredToken struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// bcrypted version of the token that was issued to the user
	Bcrypted []byte `protobuf:"bytes,1,opt,name=bcrypted,proto3" json:"bcrypted,omitempty"`
	// when this token expires
	ExpiresAt *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=expires_at,proto3" json:"expires_at,omitempty"`
}

func (x *StoredToken) Reset() {
	*x = StoredToken{}
	if protoimpl.UnsafeEnabled {
		mi := &file_storage_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StoredToken) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoredToken) ProtoMessage() {}

func (x *StoredToken) ProtoReflect() protoreflect.Message {
	mi := &file_storage_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoredToken.ProtoReflect.Descriptor instead.
func (*StoredToken) Descriptor() ([]byte, []int) {
	return file_storage_proto_rawDescGZIP(), []int{0}
}

func (x *StoredToken) GetBcrypted() []byte {
	if x != nil {
		return x.Bcrypted
	}
	return nil
}

func (x *StoredToken) GetExpiresAt() *timestamppb.Timestamp {
	if x != nil {
		return x.ExpiresAt
	}
	return nil
}

// UserToken is the value we issue directly to users. The message is serialized,
// then base64 encoded to make up the issued version.
type UserToken struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// the ID of the session this token corresponds to
	SessionId string `protobuf:"bytes,1,opt,name=session_id,proto3" json:"session_id,omitempty"`
	// the token itself, to be compared to the bcrypt version on the backend
	Token []byte `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *UserToken) Reset() {
	*x = UserToken{}
	if protoimpl.UnsafeEnabled {
		mi := &file_storage_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserToken) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserToken) ProtoMessage() {}

func (x *UserToken) ProtoReflect() protoreflect.Message {
	mi := &file_storage_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserToken.ProtoReflect.Descriptor instead.
func (*UserToken) Descriptor() ([]byte, []int) {
	return file_storage_proto_rawDescGZIP(), []int{1}
}

func (x *UserToken) GetSessionId() string {
	if x != nil {
		return x.SessionId
	}
	return ""
}

func (x *UserToken) GetToken() []byte {
	if x != nil {
		return x.Token
	}
	return nil
}

var File_storage_proto protoreflect.FileDescriptor

var file_storage_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0c, 0x6f, 0x69, 0x64, 0x63, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x65,
	0x0a, 0x0b, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x64, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x1a, 0x0a,
	0x08, 0x62, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x08, 0x62, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x12, 0x3a, 0x0a, 0x0a, 0x65, 0x78, 0x70,
	0x69, 0x72, 0x65, 0x73, 0x5f, 0x61, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72,
	0x65, 0x73, 0x5f, 0x61, 0x74, 0x22, 0x41, 0x0a, 0x09, 0x55, 0x73, 0x65, 0x72, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x12, 0x1e, 0x0a, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f,
	0x69, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x42, 0x08, 0x5a, 0x06, 0x2e, 0x3b, 0x63, 0x6f,
	0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_storage_proto_rawDescOnce sync.Once
	file_storage_proto_rawDescData = file_storage_proto_rawDesc
)

func file_storage_proto_rawDescGZIP() []byte {
	file_storage_proto_rawDescOnce.Do(func() {
		file_storage_proto_rawDescData = protoimpl.X.CompressGZIP(file_storage_proto_rawDescData)
	})
	return file_storage_proto_rawDescData
}

var file_storage_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_storage_proto_goTypes = []interface{}{
	(*StoredToken)(nil),           // 0: oidc.oidcop.v1.StoredToken
	(*UserToken)(nil),             // 1: oidc.oidcop.v1.UserToken
	(*timestamppb.Timestamp)(nil), // 2: google.protobuf.Timestamp
}
var file_storage_proto_depIdxs = []int32{
	2, // 0: oidc.oidcop.v1.StoredToken.expires_at:type_name -> google.protobuf.Timestamp
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_storage_proto_init() }
func file_storage_proto_init() {
	if File_storage_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_storage_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StoredToken); i {
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
		file_storage_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserToken); i {
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
			RawDescriptor: file_storage_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_storage_proto_goTypes,
		DependencyIndexes: file_storage_proto_depIdxs,
		MessageInfos:      file_storage_proto_msgTypes,
	}.Build()
	File_storage_proto = out.File
	file_storage_proto_rawDesc = nil
	file_storage_proto_goTypes = nil
	file_storage_proto_depIdxs = nil
}
