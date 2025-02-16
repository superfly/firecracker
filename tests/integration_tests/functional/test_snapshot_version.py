# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import platform
import pytest
from framework.builder import SnapshotBuilder
import host_tools.network as net_tools  # pylint: disable=import-error

# Firecracker v0.23 used 16 IRQ lines. For virtio devices,
# IRQs are available from 5 to 23, so the maximum number
# of devices allowed at the same time was 11.
FC_V0_23_MAX_DEVICES_ATTACHED = 11


def _create_and_start_microvm_with_net_devices(test_microvm,
                                               network_config,
                                               devices_no):
    test_microvm.spawn()
    # Set up a basic microVM: configure the boot source and
    # add a root device.
    test_microvm.basic_config(track_dirty_pages=True)

    # Add network devices on top of the already configured rootfs for a
    # total of (`devices_no` + 1) devices.
    for i in range(devices_no):
        # Create tap before configuring interface.
        _tap, _host_ip, _guest_ip = test_microvm.ssh_network_config(
            network_config,
            str(i)
        )
    test_microvm.start()

    ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
    # Verify if guest can run commands.
    exit_code, _, _ = ssh_connection.execute_command("sync")
    assert exit_code == 0


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_create_with_past_version(test_microvm_with_ssh, network_config):
    """Test scenario: restore in previous versions with too many devices."""
    test_microvm = test_microvm_with_ssh

    # Create and start a microVM with (`FC_V0_23_MAX_DEVICES_ATTACHED` - 1)
    # network devices.
    devices_no = FC_V0_23_MAX_DEVICES_ATTACHED - 1
    _create_and_start_microvm_with_net_devices(test_microvm,
                                               network_config,
                                               devices_no)

    snapshot_builder = SnapshotBuilder(test_microvm)
    # Create directory and files for saving snapshot state and memory.
    _snapshot_dir = snapshot_builder.create_snapshot_dir()

    # Pause and create a snapshot of the microVM. Firecracker v0.23 allowed a
    # maximum of `FC_V0_23_MAX_DEVICES_ATTACHED` virtio devices at a time.
    # This microVM has `FC_V0_23_MAX_DEVICES_ATTACHED` devices, including the
    # rootfs, so snapshotting should succeed.
    test_microvm.pause_to_snapshot(
        mem_file_path="/snapshot/vm.mem",
        snapshot_path="/snapshot/vm.vmstate",
        diff=True,
        version="0.23.0")


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Not supported yet."
)
def test_create_with_too_many_devices(test_microvm_with_ssh, network_config):
    """Test scenario: restore in previous versions with too many devices."""
    test_microvm = test_microvm_with_ssh

    # Create and start a microVM with `FC_V0_23_MAX_DEVICES_ATTACHED`
    # network devices.
    devices_no = FC_V0_23_MAX_DEVICES_ATTACHED
    _create_and_start_microvm_with_net_devices(test_microvm,
                                               network_config,
                                               devices_no)

    snapshot_builder = SnapshotBuilder(test_microvm)
    # Create directory and files for saving snapshot state and memory.
    _snapshot_dir = snapshot_builder.create_snapshot_dir()

    # Pause microVM for snapshot.
    response = test_microvm.vm.patch(state='Paused')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Attempt to create a snapshot with version: `0.23.0`. Firecracker
    # v0.23 allowed a maximum of `FC_V0_23_MAX_DEVICES_ATTACHED` virtio
    # devices at a time. This microVM has `FC_V0_23_MAX_DEVICES_ATTACHED`
    # network devices on top of the rootfs, so the limit is exceeded.
    response = test_microvm.snapshot.create(
        mem_file_path="/snapshot/vm.vmstate",
        snapshot_path="/snapshot/vm.mem",
        diff=True,
        version="0.23.0"
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Too many devices attached" in response.text
