# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from .switch import SwitchConnection
from p4.tmp import p4config_pb2


def buildDeviceConfig(bmv2_json_file_path=None):
    "Builds the device config for BMv2"
    device_config = p4config_pb2.P4DeviceConfig()
    device_config.reassign = True
    with open(bmv2_json_file_path) as f:
        device_config.device_data = f.read().encode('utf-8')
    return device_config


class Bmv2SwitchConnection(SwitchConnection):
    def buildDeviceConfig(self, **kwargs):
        return buildDeviceConfig(**kwargs)

    def insertTableEntry(self, p4info_helper, entry=None,
                         table_name=None, match_fields=None, action_name=None,
                         default_action=None, action_params=None, priority=None):
        if entry is not None:
            table_name = entry['table_name']
            match_fields = entry.get('match_fields')  # None if not found
            action_name = entry['action_name']
            default_action = entry.get('default_action')  # None if not found
            action_params = entry['action_params']
            priority = entry.get('priority')  # None if not found

        table_entry = p4info_helper.buildTableEntry(
            table_name=table_name,
            match_fields=match_fields,
            default_action=default_action,
            action_name=action_name,
            action_params=action_params,
            priority=priority)

        self.WriteTableEntry(table_entry)

    def addMulticastGroup(self, p4info_helper, mgid=None, ports=None):
        group = p4info_helper.buildMulticastGroupEntry(mgid=mgid, ports=ports)
        self.CreateMulticastGroup(group)

    def removeTableEntry(self, p4info_helper, entry=None,
                         table_name=None, match_fields=None, action_name=None,
                         default_action=None, action_params=None, priority=None):
        if entry is not None:
            table_name = entry['table_name']
            match_fields = entry.get('match_fields')  # None if not found
            action_name = entry['action_name']
            default_action = entry.get('default_action')  # None if not found
            action_params = entry['action_params']
            priority = entry.get('priority')  # None if not found

        table_entry = p4info_helper.buildTableEntry(
            table_name=table_name,
            match_fields=match_fields,
            default_action=default_action,
            action_name=action_name,
            action_params=action_params,
            priority=priority)

        self.DeleteTableEntry(table_entry)
