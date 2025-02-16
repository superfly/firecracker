# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define some helpers methods to create microvms from artifacts."""

import json
import os
import tempfile
from pathlib import Path
from conftest import init_microvm
from framework.artifacts import (
    Artifact, DiskArtifact, Snapshot, SnapshotType, NetIfaceConfig
)
import framework.utils as utils
import host_tools.logging as log_tools
import host_tools.network as net_tools


class MicrovmBuilder:
    """Build fresh microvms or restore from snapshot."""

    ROOT_PREFIX = "fctest-"

    def __init__(self, bin_cloner_path,
                 fc_binary=None,
                 jailer_binary=None):
        """Initialize microvm root and cloning binary."""
        self.bin_cloner_path = bin_cloner_path
        self.init_root_path()

        # Update permissions for custom binaries.
        if fc_binary is not None:
            os.chmod(fc_binary, 0o555)
        if jailer_binary is not None:
            os.chmod(jailer_binary, 0o555)

        self._fc_binary = fc_binary
        self._jailer_binary = jailer_binary

    @property
    def root_path(self):
        """Return the root path of the microvm."""
        return self._root_path

    def init_root_path(self):
        """Initialize microvm root path."""
        self._root_path = tempfile.mkdtemp(MicrovmBuilder.ROOT_PREFIX)

    def build(self,
              kernel: Artifact,
              disks: [DiskArtifact],
              ssh_key: Artifact,
              config: Artifact,
              net_ifaces=None,
              enable_diff_snapshots=False,
              cpu_template=None,
              use_ramdisk=False):
        """Build a fresh microvm."""
        vm = init_microvm(self.root_path, self.bin_cloner_path,
                          self._fc_binary, self._jailer_binary)

        # Start firecracker.
        vm.spawn(use_ramdisk=use_ramdisk)

        # Link the microvm to kernel, rootfs, ssh_key artifacts.
        vm.kernel_file = kernel.local_path()
        vm.rootfs_file = disks[0].local_path()
        # copy rootfs to ramdisk if needed
        jailed_rootfs_path = vm.copy_to_jail_ramfs(vm.rootfs_file) if \
            use_ramdisk else vm.create_jailed_resource(vm.rootfs_file)

        # Download ssh key into the microvm root.
        ssh_key.download(self.root_path)
        vm.ssh_config['ssh_key_path'] = ssh_key.local_path()
        os.chmod(vm.ssh_config['ssh_key_path'], 0o400)

        # Provide a default network configuration.
        if net_ifaces is None or len(net_ifaces) == 0:
            ifaces = [NetIfaceConfig()]
        else:
            ifaces = net_ifaces

        # Configure network interfaces using artifacts.
        for iface in ifaces:
            vm.create_tap_and_ssh_config(host_ip=iface.host_ip,
                                         guest_ip=iface.guest_ip,
                                         netmask_len=iface.netmask,
                                         tapname=iface.tap_name)
            guest_mac = net_tools.mac_from_ip(iface.guest_ip)
            response = vm.network.put(
                iface_id=iface.dev_name,
                host_dev_name=iface.tap_name,
                guest_mac=guest_mac,
                allow_mmds_requests=True,
            )
            assert vm.api_session.is_status_no_content(response.status_code)

        with open(config.local_path()) as microvm_config_file:
            microvm_config = json.load(microvm_config_file)

        response = vm.basic_config(
            add_root_device=False,
            boot_args='console=ttyS0 reboot=k panic=1'
        )

        # Add the root file system with rw permissions.
        response = vm.drive.put(
            drive_id='rootfs',
            path_on_host=jailed_rootfs_path,
            is_root_device=True,
            is_read_only=False
        )
        assert vm.api_session \
            .is_status_no_content(response.status_code), \
            response.text

        # Apply the microvm artifact configuration and template.
        response = vm.machine_cfg.put(
            vcpu_count=int(microvm_config['vcpu_count']),
            mem_size_mib=int(microvm_config['mem_size_mib']),
            ht_enabled=bool(microvm_config['ht_enabled']),
            track_dirty_pages=enable_diff_snapshots,
            cpu_template=cpu_template,
        )
        assert vm.api_session.is_status_no_content(response.status_code)

        vm.vcpus_count = int(microvm_config['vcpu_count'])

        # Reset root path so next microvm is built some place else.
        self.init_root_path()
        return vm

    # This function currently returns the vm and a metrics_fifo which
    # is needed by the performance integration tests.
    # TODO: Move all metrics functionality to microvm (encapsulating the fifo)
    # so we do not need to move it around polluting the code.
    def build_from_snapshot(self,
                            snapshot: Snapshot,
                            resume=False,
                            # Enable incremental snapshot capability.
                            enable_diff_snapshots=False):
        """Build a microvm from a snapshot artifact."""
        vm = init_microvm(self.root_path, self.bin_cloner_path,
                          self._fc_binary, self._jailer_binary)
        vm.spawn(log_level='Info')

        metrics_file_path = os.path.join(vm.path, 'metrics.log')
        metrics_fifo = log_tools.Fifo(metrics_file_path)
        response = vm.metrics.put(
            metrics_path=vm.create_jailed_resource(metrics_fifo.path)
        )
        assert vm.api_session.is_status_no_content(response.status_code)

        # Hardlink all the snapshot files into the microvm jail.
        jailed_mem = vm.create_jailed_resource(snapshot.mem)
        jailed_vmstate = vm.create_jailed_resource(snapshot.vmstate)
        assert len(snapshot.disks) > 0, "Snapshot requires at least one disk."
        _jailed_disks = []
        for disk in snapshot.disks:
            _jailed_disks.append(vm.create_jailed_resource(disk))
        vm.ssh_config['ssh_key_path'] = snapshot.ssh_key

        # Create network interfaces.
        for iface in snapshot.net_ifaces:
            vm.create_tap_and_ssh_config(host_ip=iface.host_ip,
                                         guest_ip=iface.guest_ip,
                                         netmask_len=iface.netmask,
                                         tapname=iface.tap_name)
        response = vm.snapshot.load(mem_file_path=jailed_mem,
                                    snapshot_path=jailed_vmstate,
                                    diff=enable_diff_snapshots,
                                    resume=resume)
        assert vm.api_session.is_status_no_content(response.status_code)

        # Reset root path so next microvm is built some place else.
        self.init_root_path()

        # Return a resumed microvm.
        return vm, metrics_fifo

    def create_basevm(self):
        """Create a clean VM in an initial state."""
        return init_microvm(self.root_path, self.bin_cloner_path,
                            self._fc_binary, self._jailer_binary)


class SnapshotBuilder:  # pylint: disable=too-few-public-methods
    """Create a snapshot from a running microvm."""

    def __init__(self, microvm):
        """Initialize the snapshot builder."""
        self._microvm = microvm

    def create_snapshot_dir(self):
        """Create dir and files for saving snapshot state and memory."""
        chroot_path = self._microvm.jailer.chroot_path()
        snapshot_dir = os.path.join(chroot_path, "snapshot")
        Path(snapshot_dir).mkdir(parents=True, exist_ok=True)
        cmd = 'chown {}:{} {}'.format(self._microvm.jailer.uid,
                                      self._microvm.jailer.gid,
                                      snapshot_dir)
        utils.run_cmd(cmd)
        return snapshot_dir

    def create(self,
               disks,
               ssh_key: Artifact,
               snapshot_type: SnapshotType = SnapshotType.FULL,
               target_version: str = None,
               mem_file_name: str = "vm.mem",
               snapshot_name: str = "vm.vmstate",
               net_ifaces=None,
               use_ramdisk=False):
        """Create a Snapshot object from a microvm and artifacts."""
        if use_ramdisk:
            snaps_dir = self._microvm.jailer.chroot_ramfs_path()
            mem_full_path = os.path.join(snaps_dir, mem_file_name)
            vmstate_full_path = os.path.join(snaps_dir, snapshot_name)

            memsize = self._microvm.machine_cfg.configuration['mem_size_mib']
            # Pre-allocate ram for memfile to eliminate allocation variability.
            utils.run_cmd('dd if=/dev/zero of={} bs=1M count={}'.format(
                mem_full_path, memsize
            ))
            cmd = 'chown {}:{} {}'.format(
                self._microvm.jailer.uid,
                self._microvm.jailer.gid,
                mem_full_path
            )
            utils.run_cmd(cmd)
        else:
            snaps_dir = self.create_snapshot_dir()
            mem_full_path = os.path.join(snaps_dir, mem_file_name)
            vmstate_full_path = os.path.join(snaps_dir, snapshot_name)

        snaps_dir_name = os.path.basename(snaps_dir)
        self._microvm.pause_to_snapshot(
            mem_file_path=os.path.join('/', snaps_dir_name, mem_file_name),
            snapshot_path=os.path.join('/', snaps_dir_name, snapshot_name),
            diff=snapshot_type == SnapshotType.DIFF,
            version=target_version)

        # Create a copy of the ssh_key artifact.
        ssh_key_copy = ssh_key.copy()
        return Snapshot(mem=mem_full_path,
                        vmstate=vmstate_full_path,
                        # TODO: To support more disks we need to figure out a
                        # simple and flexible way to store snapshot artifacts
                        # in S3. This should be done in a PR where we add tests
                        # that resume from S3 snapshot artifacts.
                        disks=disks,
                        net_ifaces=net_ifaces or [NetIfaceConfig()],
                        ssh_key=ssh_key_copy.local_path())
