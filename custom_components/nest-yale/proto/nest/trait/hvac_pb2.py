# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: nest/trait/hvac.proto
# Protobuf Python Version: 5.29.3
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    3,
    '',
    'nest/trait/hvac.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import any_pb2 as google_dot_protobuf_dot_any__pb2
from ...weave import common_pb2 as weave_dot_common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x15nest/trait/hvac.proto\x12\x0fnest.trait.hvac\x1a\x19google/protobuf/any.proto\x1a\x12weave/common.proto\"\xe5\x03\n\x1eTargetTemperatureSettingsTrait\x12U\n\x08settings\x18\x01 \x01(\x0b\x32\x43.nest.trait.hvac.TargetTemperatureSettingsTrait.TemperatureSetPoint\x12/\n\x06\x61\x63tive\x18\x02 \x01(\x0b\x32\x1f.nest.trait.hvac.Int32_Indirect\x1a\xba\x02\n\x13TemperatureSetPoint\x12\x30\n\thvac_mode\x18\x01 \x01(\x0e\x32\x1d.nest.trait.hvac.HeatCoolMode\x12@\n\x17target_temperature_heat\x18\x04 \x01(\x0b\x32\x1f.nest.trait.hvac.Float_Indirect\x12@\n\x17target_temperature_cool\x18\x05 \x01(\x0b\x32\x1f.nest.trait.hvac.Float_Indirect\x12\x31\n\x0bupdate_info\x18\x06 \x01(\x0b\x32\x1c.nest.trait.hvac.UpdateStamp\x12:\n\x14original_update_info\x18\x07 \x01(\x0b\x32\x1c.nest.trait.hvac.UpdateStamp\"\xce\x01\n\x10HvacControlTrait\x12=\n\x08settings\x18\x01 \x01(\x0b\x32+.nest.trait.hvac.HvacControlTrait.HvacState\x12\x12\n\nis_delayed\x18\x02 \x01(\x05\x12\x32\n\ttimestamp\x18\x03 \x01(\x0b\x32\x1f.nest.trait.hvac.Int32_Indirect\x1a\x33\n\tHvacState\x12\x12\n\nis_cooling\x18\x01 \x01(\x05\x12\x12\n\nis_heating\x18\x04 \x01(\x05\"\xbd\x01\n\x11\x45\x63oModeStateTrait\x12\x32\n\x0b\x65\x63o_enabled\x18\x01 \x01(\x0e\x32\x1d.nest.trait.hvac.EcoModeState\x12\x41\n\x13\x65\x63oModeChangeReason\x18\x02 \x01(\x0e\x32$.nest.trait.hvac.EcoModeChangeReason\x12\x31\n\x0bupdate_info\x18\x03 \x01(\x0b\x32\x1c.nest.trait.hvac.UpdateStamp\"\xa5\x02\n\x14\x45\x63oModeSettingsTrait\x12\x18\n\x10\x61uto_eco_enabled\x18\x01 \x01(\x05\x12H\n\x03low\x18\x02 \x01(\x0b\x32;.nest.trait.hvac.EcoModeSettingsTrait.EcoTemperatureSetting\x12I\n\x04high\x18\x03 \x01(\x0b\x32;.nest.trait.hvac.EcoModeSettingsTrait.EcoTemperatureSetting\x1a^\n\x15\x45\x63oTemperatureSetting\x12\x34\n\x0btemperature\x18\x01 \x01(\x0b\x32\x1f.nest.trait.hvac.Float_Indirect\x12\x0f\n\x07\x65nabled\x18\x02 \x01(\x05\"X\n\x14\x44isplaySettingsTrait\x12\x0f\n\x07\x65nabled\x18\x01 \x01(\x05\x12/\n\x05units\x18\x02 \x01(\x0e\x32 .nest.trait.hvac.TemperatureUnit\"\xc3\x06\n\x17\x46\x61nControlSettingsTrait\x12>\n\x04mode\x18\x01 \x01(\x0e\x32\x30.nest.trait.hvac.FanControlSettingsTrait.FanMode\x12S\n\x11hvacOverrideSpeed\x18\x02 \x01(\x0e\x32\x38.nest.trait.hvac.FanControlSettingsTrait.FanSpeedSetting\x12O\n\rscheduleSpeed\x18\x03 \x01(\x0e\x32\x38.nest.trait.hvac.FanControlSettingsTrait.FanSpeedSetting\x12\x19\n\x11scheduleDutyCycle\x18\x04 \x01(\r\x12\x19\n\x11scheduleStartTime\x18\x05 \x01(\r\x12\x17\n\x0fscheduleEndTime\x18\x06 \x01(\r\x12L\n\ntimerSpeed\x18\x07 \x01(\x0e\x32\x38.nest.trait.hvac.FanControlSettingsTrait.FanSpeedSetting\x12\x38\n\x0f\x66\x61nTimerTimeout\x18\x08 \x01(\x0b\x32\x1f.nest.trait.hvac.Int32_Indirect\x12\x36\n\rtimerDuration\x18\t \x01(\x0b\x32\x1f.nest.trait.hvac.Int32_Indirect\"k\n\x07\x46\x61nMode\x12\x18\n\x14\x46\x41N_MODE_UNSPECIFIED\x10\x00\x12\x11\n\rFAN_MODE_AUTO\x10\x01\x12\x1a\n\x16\x46\x41N_MODE_CONTINUOUS_ON\x10\x02\x12\x17\n\x13\x46\x41N_MODE_DUTY_CYCLE\x10\x03\"\xc5\x01\n\x0f\x46\x61nSpeedSetting\x12!\n\x1d\x46\x41N_SPEED_SETTING_UNSPECIFIED\x10\x00\x12\x1c\n\x18\x46\x41N_SPEED_SETTING_STAGE1\x10\x01\x12\x1c\n\x18\x46\x41N_SPEED_SETTING_STAGE2\x10\x02\x12\x1c\n\x18\x46\x41N_SPEED_SETTING_STAGE3\x10\x03\x12\x19\n\x15\x46\x41N_SPEED_SETTING_OFF\x10\x04\x12\x1a\n\x16\x46\x41N_SPEED_SETTING_AUTO\x10\x05\"\xc2\x02\n\x0f\x46\x61nControlTrait\x12\x46\n\x0c\x63urrentSpeed\x18\x01 \x01(\x0e\x32\x30.nest.trait.hvac.FanControlTrait.FanSpeedSetting\x12\x1f\n\x17userRequestedFanRunning\x18\x02 \x01(\x08\"\xc5\x01\n\x0f\x46\x61nSpeedSetting\x12!\n\x1d\x46\x41N_SPEED_SETTING_UNSPECIFIED\x10\x00\x12\x1c\n\x18\x46\x41N_SPEED_SETTING_STAGE1\x10\x01\x12\x1c\n\x18\x46\x41N_SPEED_SETTING_STAGE2\x10\x02\x12\x1c\n\x18\x46\x41N_SPEED_SETTING_STAGE3\x10\x03\x12\x19\n\x15\x46\x41N_SPEED_SETTING_OFF\x10\x04\x12\x1a\n\x16\x46\x41N_SPEED_SETTING_AUTO\x10\x05\"\x96\x01\n\x12\x42\x61\x63kplateInfoTrait\x12\x15\n\rserial_number\x18\x01 \x01(\t\x12\x17\n\x0f\x62\x61\x63kplate_model\x18\x02 \x01(\t\x12\x12\n\nos_version\x18\x03 \x01(\t\x12\x17\n\x0fos_build_string\x18\x04 \x01(\t\x12\x12\n\nsw_version\x18\x05 \x01(\t\x12\x0f\n\x07sw_info\x18\x06 \x01(\t\"D\n\x1eHvacEquipmentCapabilitiesTrait\x12\x10\n\x08\x63\x61n_cool\x18\x01 \x01(\x05\x12\x10\n\x08\x63\x61n_heat\x18\x04 \x01(\x05\"\x8c\x10\n!RemoteComfortSensingSettingsTrait\x12Y\n\x0ercsControlMode\x18\x01 \x01(\x0e\x32\x41.nest.trait.hvac.RemoteComfortSensingSettingsTrait.RcsControlMode\x12\x61\n\x12\x61\x63tiveRcsSelection\x18\x02 \x01(\x0b\x32\x45.nest.trait.hvac.RemoteComfortSensingSettingsTrait.RcsSourceSelection\x12\\\n\x14\x61ssociatedRcsSensors\x18\x04 \x03(\x0b\x32>.nest.trait.hvac.RemoteComfortSensingSettingsTrait.RcsSensorId\x12\x63\n\x13multiSensorSettings\x18\x05 \x01(\x0b\x32\x46.nest.trait.hvac.RemoteComfortSensingSettingsTrait.MultiSensorSettings\x1a^\n\x0bRcsSensorId\x12*\n\x08\x64\x65viceId\x18\x01 \x01(\x0b\x32\x18.weave.common.ResourceId\x12\x10\n\x08vendorId\x18\x02 \x01(\r\x12\x11\n\tproductId\x18\x03 \x01(\r\x1a\x65\n\x13MultiSensorSettings\x12\x1a\n\x12multiSensorEnabled\x18\x01 \x01(\x08\x12\x32\n\x10multiSensorGroup\x18\x02 \x03(\x0b\x32\x18.weave.common.ResourceId\x1a\xa0\x01\n\x12RcsSourceSelection\x12W\n\rrcsSourceType\x18\x01 \x01(\x0e\x32@.nest.trait.hvac.RemoteComfortSensingSettingsTrait.RcsSourceType\x12\x31\n\x0f\x61\x63tiveRcsSensor\x18\x02 \x01(\x0b\x32\x18.weave.common.ResourceId\x1a\x9e\x01\n\x0bRcsInterval\x12[\n\x0crcsSelection\x18\x01 \x01(\x0b\x32\x45.nest.trait.hvac.RemoteComfortSensingSettingsTrait.RcsSourceSelection\x12\x19\n\x11startSecondsInDay\x18\x02 \x01(\r\x12\x17\n\x0f\x65ndSecondsInDay\x18\x03 \x01(\r\x1a\xe1\x01\n\x0bRcsSchedule\x12`\n\tintervals\x18\x01 \x03(\x0b\x32M.nest.trait.hvac.RemoteComfortSensingSettingsTrait.RcsSchedule.IntervalsEntry\x1ap\n\x0eIntervalsEntry\x12\x0b\n\x03key\x18\x01 \x01(\r\x12M\n\x05value\x18\x02 \x01(\x0b\x32>.nest.trait.hvac.RemoteComfortSensingSettingsTrait.RcsInterval:\x02\x38\x01\x1aI\n\x19\x41ssociateRcsSensorRequest\x12,\n\nresourceId\x18\x01 \x01(\x0b\x32\x18.weave.common.ResourceId\x1ak\n\x1a\x41ssociateRcsSensorResponse\x12M\n\x06status\x18\x01 \x01(\x0e\x32=.nest.trait.hvac.RemoteComfortSensingSettingsTrait.StatusCode\x1aJ\n\x1a\x44issociateRcsSensorRequest\x12,\n\nresourceId\x18\x01 \x01(\x0b\x32\x18.weave.common.ResourceId\x1al\n\x1b\x44issociateRcsSensorResponse\x12M\n\x06status\x18\x01 \x01(\x0e\x32=.nest.trait.hvac.RemoteComfortSensingSettingsTrait.StatusCode\"\x94\x01\n\x0eRcsControlMode\x12 \n\x1cRCS_CONTROL_MODE_UNSPECIFIED\x10\x00\x12\x19\n\x15RCS_CONTROL_MODE_HOLD\x10\x01\x12\x1d\n\x19RCS_CONTROL_MODE_SCHEDULE\x10\x02\x12&\n\"RCS_CONTROL_MODE_SCHEDULE_OVERRIDE\x10\x03\"\x94\x01\n\rRcsSourceType\x12\x1f\n\x1bRCS_SOURCE_TYPE_UNSPECIFIED\x10\x00\x12\x1d\n\x19RCS_SOURCE_TYPE_BACKPLATE\x10\x01\x12!\n\x1dRCS_SOURCE_TYPE_SINGLE_SENSOR\x10\x02\x12 \n\x1cRCS_SOURCE_TYPE_MULTI_SENSOR\x10\x03\"\xd6\x01\n\nStatusCode\x12\x1b\n\x17STATUS_CODE_UNSPECIFIED\x10\x00\x12\x17\n\x13STATUS_CODE_SUCCESS\x10\x01\x12\x17\n\x13STATUS_CODE_FAILURE\x10\x02\x12*\n%STATUS_CODE_SENSOR_ALREADY_ASSOCIATED\x10\x80 \x12%\n STATUS_CODE_SENSOR_LIMIT_REACHED\x10\x81 \x12&\n!STATUS_CODE_SENSOR_NOT_ASSOCIATED\x10\x80@\"\xad\x01\n\x0bUpdateStamp\x12\x34\n\rupdate_source\x18\x01 \x01(\x0e\x32\x1d.nest.trait.hvac.UpdateSource\x12\x34\n\nupdated_by\x18\x02 \x01(\x0b\x32 .nest.trait.hvac.String_Indirect\x12\x32\n\ttimestamp\x18\x03 \x01(\x0b\x32\x1f.nest.trait.hvac.Int32_Indirect\" \n\x0fString_Indirect\x12\r\n\x05value\x18\x01 \x01(\t\"\x1f\n\x0e\x46loat_Indirect\x12\r\n\x05value\x18\x01 \x01(\x02\"\x1f\n\x0eInt32_Indirect\x12\r\n\x05value\x18\x01 \x01(\x05*C\n\x0cHeatCoolMode\x12\x14\n\x10INVALID_HEATCOOL\x10\x00\x12\x08\n\x04HEAT\x10\x01\x12\x08\n\x04\x43OOL\x10\x02\x12\t\n\x05RANGE\x10\x03*0\n\x0c\x45\x63oModeState\x12\x0f\n\x0bINVALID_ECO\x10\x00\x12\x07\n\x03OFF\x10\x01\x12\x06\n\x02ON\x10\x02*\x84\x02\n\x13\x45\x63oModeChangeReason\x12&\n\"ECO_MODE_CHANGE_REASON_UNSPECIFIED\x10\x00\x12!\n\x1d\x45\x43O_MODE_CHANGE_REASON_MANUAL\x10\x01\x12)\n%ECO_MODE_CHANGE_REASON_STRUCTURE_MODE\x10\x02\x12$\n ECO_MODE_CHANGE_REASON_OCCUPANCY\x10\x03\x12&\n\"ECO_MODE_CHANGE_REASON_TEMPERATURE\x10\x04\x12)\n%ECO_MODE_CHANGE_REASON_FEATURE_ENABLE\x10\x05*e\n\x0cUpdateSource\x12\x12\n\x0eINVALID_UPDATE\x10\x00\x12\r\n\tINVALID_1\x10\x01\x12\r\n\tINVALID_2\x10\x02\x12\n\n\x06\x44\x45VICE\x10\x03\x12\r\n\tINVALID_4\x10\x04\x12\x08\n\x04USER\x10\x05*A\n\x0fTemperatureUnit\x12\x10\n\x0cINVALID_TEMP\x10\x00\x12\r\n\tDEGREES_C\x10\x01\x12\r\n\tDEGREES_F\x10\x02\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'nest.trait.hvac_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSCHEDULE_INTERVALSENTRY']._loaded_options = None
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSCHEDULE_INTERVALSENTRY']._serialized_options = b'8\001'
  _globals['_HEATCOOLMODE']._serialized_start=5089
  _globals['_HEATCOOLMODE']._serialized_end=5156
  _globals['_ECOMODESTATE']._serialized_start=5158
  _globals['_ECOMODESTATE']._serialized_end=5206
  _globals['_ECOMODECHANGEREASON']._serialized_start=5209
  _globals['_ECOMODECHANGEREASON']._serialized_end=5469
  _globals['_UPDATESOURCE']._serialized_start=5471
  _globals['_UPDATESOURCE']._serialized_end=5572
  _globals['_TEMPERATUREUNIT']._serialized_start=5574
  _globals['_TEMPERATUREUNIT']._serialized_end=5639
  _globals['_TARGETTEMPERATURESETTINGSTRAIT']._serialized_start=90
  _globals['_TARGETTEMPERATURESETTINGSTRAIT']._serialized_end=575
  _globals['_TARGETTEMPERATURESETTINGSTRAIT_TEMPERATURESETPOINT']._serialized_start=261
  _globals['_TARGETTEMPERATURESETTINGSTRAIT_TEMPERATURESETPOINT']._serialized_end=575
  _globals['_HVACCONTROLTRAIT']._serialized_start=578
  _globals['_HVACCONTROLTRAIT']._serialized_end=784
  _globals['_HVACCONTROLTRAIT_HVACSTATE']._serialized_start=733
  _globals['_HVACCONTROLTRAIT_HVACSTATE']._serialized_end=784
  _globals['_ECOMODESTATETRAIT']._serialized_start=787
  _globals['_ECOMODESTATETRAIT']._serialized_end=976
  _globals['_ECOMODESETTINGSTRAIT']._serialized_start=979
  _globals['_ECOMODESETTINGSTRAIT']._serialized_end=1272
  _globals['_ECOMODESETTINGSTRAIT_ECOTEMPERATURESETTING']._serialized_start=1178
  _globals['_ECOMODESETTINGSTRAIT_ECOTEMPERATURESETTING']._serialized_end=1272
  _globals['_DISPLAYSETTINGSTRAIT']._serialized_start=1274
  _globals['_DISPLAYSETTINGSTRAIT']._serialized_end=1362
  _globals['_FANCONTROLSETTINGSTRAIT']._serialized_start=1365
  _globals['_FANCONTROLSETTINGSTRAIT']._serialized_end=2200
  _globals['_FANCONTROLSETTINGSTRAIT_FANMODE']._serialized_start=1893
  _globals['_FANCONTROLSETTINGSTRAIT_FANMODE']._serialized_end=2000
  _globals['_FANCONTROLSETTINGSTRAIT_FANSPEEDSETTING']._serialized_start=2003
  _globals['_FANCONTROLSETTINGSTRAIT_FANSPEEDSETTING']._serialized_end=2200
  _globals['_FANCONTROLTRAIT']._serialized_start=2203
  _globals['_FANCONTROLTRAIT']._serialized_end=2525
  _globals['_FANCONTROLTRAIT_FANSPEEDSETTING']._serialized_start=2003
  _globals['_FANCONTROLTRAIT_FANSPEEDSETTING']._serialized_end=2200
  _globals['_BACKPLATEINFOTRAIT']._serialized_start=2528
  _globals['_BACKPLATEINFOTRAIT']._serialized_end=2678
  _globals['_HVACEQUIPMENTCAPABILITIESTRAIT']._serialized_start=2680
  _globals['_HVACEQUIPMENTCAPABILITIESTRAIT']._serialized_end=2748
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT']._serialized_start=2751
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT']._serialized_end=4811
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSENSORID']._serialized_start=3173
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSENSORID']._serialized_end=3267
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_MULTISENSORSETTINGS']._serialized_start=3269
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_MULTISENSORSETTINGS']._serialized_end=3370
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSOURCESELECTION']._serialized_start=3373
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSOURCESELECTION']._serialized_end=3533
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSINTERVAL']._serialized_start=3536
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSINTERVAL']._serialized_end=3694
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSCHEDULE']._serialized_start=3697
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSCHEDULE']._serialized_end=3922
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSCHEDULE_INTERVALSENTRY']._serialized_start=3810
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSCHEDULE_INTERVALSENTRY']._serialized_end=3922
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_ASSOCIATERCSSENSORREQUEST']._serialized_start=3924
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_ASSOCIATERCSSENSORREQUEST']._serialized_end=3997
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_ASSOCIATERCSSENSORRESPONSE']._serialized_start=3999
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_ASSOCIATERCSSENSORRESPONSE']._serialized_end=4106
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_DISSOCIATERCSSENSORREQUEST']._serialized_start=4108
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_DISSOCIATERCSSENSORREQUEST']._serialized_end=4182
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_DISSOCIATERCSSENSORRESPONSE']._serialized_start=4184
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_DISSOCIATERCSSENSORRESPONSE']._serialized_end=4292
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSCONTROLMODE']._serialized_start=4295
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSCONTROLMODE']._serialized_end=4443
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSOURCETYPE']._serialized_start=4446
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_RCSSOURCETYPE']._serialized_end=4594
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_STATUSCODE']._serialized_start=4597
  _globals['_REMOTECOMFORTSENSINGSETTINGSTRAIT_STATUSCODE']._serialized_end=4811
  _globals['_UPDATESTAMP']._serialized_start=4814
  _globals['_UPDATESTAMP']._serialized_end=4987
  _globals['_STRING_INDIRECT']._serialized_start=4989
  _globals['_STRING_INDIRECT']._serialized_end=5021
  _globals['_FLOAT_INDIRECT']._serialized_start=5023
  _globals['_FLOAT_INDIRECT']._serialized_end=5054
  _globals['_INT32_INDIRECT']._serialized_start=5056
  _globals['_INT32_INDIRECT']._serialized_end=5087
# @@protoc_insertion_point(module_scope)
