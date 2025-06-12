#!/usr/bin/env python3
import sys
sys.path.append("/workspaces/core/config/custom_components/nest_yale/proto")
from ObserveTraits_pb2 import ObserveRequest, ResourceFilter

# Create ObserveRequest
req = ObserveRequest(version=2, subscribe=True)

# Add traits (no resourceId)
traits = [
    "weave.trait.security.BoltLockTrait",
    "weave.trait.security.BoltLockSettingsTrait",
    "weave.trait.security.BoltLockCapabilitiesTrait",
]

for trait in traits:
    filt = req.filter.add()
    filt.trait_type = trait
    # No resourceId - let API handle device specifics

# Serialize and write to file
bin_path = "/workspaces/core/config/custom_components/nest_yale/proto/ObserveTraits.bin"
with open(bin_path, "wb") as f:
    data = req.SerializeToString()
    f.write(data)

print(f"Generated ObserveTraits.bin: {len(data)} bytes - Hex: {data.hex()}")
print(f"Traits included ({len(traits)}):", traits)