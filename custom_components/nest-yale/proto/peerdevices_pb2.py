# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: weave/trait/peerdevices.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import any_pb2 as google_dot_protobuf_dot_any__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1dweave/trait/peerdevices.proto\x12\x17weave.trait.peerdevices\x1a\x19google/protobuf/any.proto\"\xde\x02\n\x10PeerDevicesTrait\x12\x45\n\x07\x64\x65vices\x18\x01 \x03(\x0b\x32\x34.weave.trait.peerdevices.PeerDevicesTrait.PeerDevice\x1a\x82\x02\n\nPeerDevice\x12Q\n\x04\x64\x61ta\x18\x02 \x01(\x0b\x32\x43.weave.trait.peerdevices.PeerDevicesTrait.PeerDevice.PeerDeviceInfo\x1a\xa0\x01\n\x0ePeerDeviceInfo\x12;\n\tdevice_id\x18\x01 \x01(\x0b\x32(.weave.trait.peerdevices.String_Indirect\x12=\n\x0b\x64\x65vice_type\x18\x02 \x01(\x0b\x32(.weave.trait.peerdevices.String_Indirect\x12\x12\n\nfw_version\x18\x05 \x01(\t\" \n\x0fString_Indirect\x12\r\n\x05value\x18\x01 \x01(\t\"\x1f\n\x0e\x46loat_Indirect\x12\r\n\x05value\x18\x01 \x01(\x02\"\x1f\n\x0eInt32_Indirect\x12\r\n\x05value\x18\x01 \x01(\x05\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'weave.trait.peerdevices_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _PEERDEVICESTRAIT._serialized_start=86
  _PEERDEVICESTRAIT._serialized_end=436
  _PEERDEVICESTRAIT_PEERDEVICE._serialized_start=178
  _PEERDEVICESTRAIT_PEERDEVICE._serialized_end=436
  _PEERDEVICESTRAIT_PEERDEVICE_PEERDEVICEINFO._serialized_start=276
  _PEERDEVICESTRAIT_PEERDEVICE_PEERDEVICEINFO._serialized_end=436
  _STRING_INDIRECT._serialized_start=438
  _STRING_INDIRECT._serialized_end=470
  _FLOAT_INDIRECT._serialized_start=472
  _FLOAT_INDIRECT._serialized_end=503
  _INT32_INDIRECT._serialized_start=505
  _INT32_INDIRECT._serialized_end=536
# @@protoc_insertion_point(module_scope)
