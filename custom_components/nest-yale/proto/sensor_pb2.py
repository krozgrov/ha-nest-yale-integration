# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: nest/trait/sensor.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import any_pb2 as google_dot_protobuf_dot_any__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x17nest/trait/sensor.proto\x12\x11nest.trait.sensor\x1a\x19google/protobuf/any.proto\"~\n\rHumidityTrait\x12\x35\n\x08humidity\x18\x01 \x01(\x0b\x32#.nest.trait.sensor.HumidityTrait.X1\x1a\x36\n\x02X1\x12\x30\n\x05value\x18\x01 \x01(\x0b\x32!.nest.trait.sensor.Float_Indirect\"\x87\x01\n\x10TemperatureTrait\x12;\n\x0btemperature\x18\x01 \x01(\x0b\x32&.nest.trait.sensor.TemperatureTrait.X1\x1a\x36\n\x02X1\x12\x30\n\x05value\x18\x01 \x01(\x0b\x32!.nest.trait.sensor.Float_Indirect\" \n\x0fString_Indirect\x12\r\n\x05value\x18\x01 \x01(\t\"\x1f\n\x0e\x46loat_Indirect\x12\r\n\x05value\x18\x01 \x01(\x02\"\x1f\n\x0eInt32_Indirect\x12\r\n\x05value\x18\x01 \x01(\x05\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'nest.trait.sensor_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _HUMIDITYTRAIT._serialized_start=73
  _HUMIDITYTRAIT._serialized_end=199
  _HUMIDITYTRAIT_X1._serialized_start=145
  _HUMIDITYTRAIT_X1._serialized_end=199
  _TEMPERATURETRAIT._serialized_start=202
  _TEMPERATURETRAIT._serialized_end=337
  _TEMPERATURETRAIT_X1._serialized_start=145
  _TEMPERATURETRAIT_X1._serialized_end=199
  _STRING_INDIRECT._serialized_start=339
  _STRING_INDIRECT._serialized_end=371
  _FLOAT_INDIRECT._serialized_start=373
  _FLOAT_INDIRECT._serialized_end=404
  _INT32_INDIRECT._serialized_start=406
  _INT32_INDIRECT._serialized_end=437
# @@protoc_insertion_point(module_scope)
