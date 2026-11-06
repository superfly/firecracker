// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring block devices.

use serde::{Deserialize, Serialize};
use vhost::vhost_user::message::VhostUserProtocolFeatures;
use vmm_sys_util::eventfd::EventFd;

use super::device::{VhostUserBlock, VhostUserBlockImpl};
use super::{NUM_QUEUES, QUEUE_SIZE, VhostUserBlockError};
use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::block::persist::BlockConstructorArgs;
use crate::devices::virtio::device::DeviceState;
use crate::devices::virtio::generated::virtio_blk::VIRTIO_BLK_F_RO;
use crate::devices::virtio::generated::virtio_ids::VIRTIO_ID_BLOCK;
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::devices::virtio::vhost_user::{VhostUserHandleBackend, VhostUserHandleImpl};
use crate::devices::virtio::vhost_user_metrics::VhostUserMetricsPerDevice;
use crate::snapshot::Persist;
use crate::utils::u64_to_usize;

/// vhost-user block device state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VhostUserBlockState {
    id: String,
    partuuid: Option<String>,
    cache_type: CacheType,
    root_device: bool,
    socket_path: String,
    vu_acked_protocol_features: u64,
    config_space: Vec<u8>,
    pub(crate) virtio_state: VirtioDeviceState,
}

impl<T: VhostUserHandleBackend> VhostUserBlockImpl<T> {
    /// Describe the device for a snapshot. [`Self::prepare_save`] must have stopped the ring, so
    /// that the queue state says where the backend stopped.
    pub fn save_state(&self) -> VhostUserBlockState
    where
        Self: crate::devices::virtio::device::VirtioDevice,
    {
        VhostUserBlockState {
            id: self.id.clone(),
            partuuid: self.partuuid.clone(),
            cache_type: self.cache_type,
            root_device: self.root_device,
            socket_path: self.vu_handle.socket_path.clone(),
            vu_acked_protocol_features: self.vu_acked_protocol_features,
            config_space: self.config_space.clone(),
            virtio_state: VirtioDeviceState::from_device(self),
        }
    }

    /// Reconnect to the backend and rebuild the device from a snapshot. The backend may be a
    /// different process from the one the snapshot was taken against: features are negotiated
    /// again and must still cover what the guest acked. The rings are handed to the backend
    /// when the device is activated, starting where the snapshot's stopped.
    pub fn restore_state(
        constructor_args: BlockConstructorArgs,
        state: &VhostUserBlockState,
    ) -> Result<Self, VhostUserBlockError> {
        let mut vu_handle = VhostUserHandleImpl::<T>::new(&state.socket_path, NUM_QUEUES)
            .map_err(VhostUserBlockError::VhostUser)?;
        let protocol_features =
            VhostUserProtocolFeatures::from_bits_truncate(state.vu_acked_protocol_features);
        let (backend_features, backend_protocol_features) = vu_handle
            .negotiate_features(state.virtio_state.avail_features, protocol_features)
            .map_err(VhostUserBlockError::VhostUser)?;
        if backend_features != state.virtio_state.avail_features
            || backend_protocol_features != state.vu_acked_protocol_features
        {
            return Err(VhostUserBlockError::RestoreFeatures {
                saved: state.virtio_state.avail_features,
                offered: backend_features,
            });
        }

        let queues = state
            .virtio_state
            .build_queues_checked(
                &constructor_args.mem,
                VIRTIO_ID_BLOCK,
                u64_to_usize(NUM_QUEUES),
                QUEUE_SIZE,
            )
            .map_err(VhostUserBlockError::Persist)?;
        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VhostUserBlockError::EventFd)?;
            u64_to_usize(NUM_QUEUES)];
        let acked_features = state.virtio_state.acked_features;
        let metrics = VhostUserMetricsPerDevice::alloc(format!("block_{}", state.id));

        Ok(Self {
            avail_features: state.virtio_state.avail_features,
            acked_features,
            config_space: state.config_space.clone(),
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VhostUserBlockError::EventFd)?,

            queues,
            queue_evts,
            device_state: DeviceState::Inactive,

            id: state.id.clone(),
            partuuid: state.partuuid.clone(),
            cache_type: state.cache_type,
            root_device: state.root_device,
            read_only: state.virtio_state.avail_features & (1 << VIRTIO_BLK_F_RO) != 0,

            vu_handle,
            vu_acked_protocol_features: state.vu_acked_protocol_features,
            metrics,
            vrings_stopped: false,
        })
    }
}

impl Persist<'_> for VhostUserBlock {
    type State = VhostUserBlockState;
    type ConstructorArgs = BlockConstructorArgs;
    type Error = VhostUserBlockError;

    fn save(&self) -> Self::State {
        self.save_state()
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        Self::restore_state(constructor_args, state)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use super::*;
    use crate::devices::virtio::block::vhost_user::device::tests::{
        RingMockFrontend, activated_ring_mock,
    };
    use crate::devices::virtio::device::VirtioDevice;
    use crate::snapshot::Snapshot;

    #[test]
    fn test_save_restore() {
        let (mut block, mem, _tmp) = activated_ring_mock();
        block.acked_features = block.avail_features;
        block.prepare_save();
        let state = block.save_state();
        assert!(state.virtio_state.activated);

        // Through the snapshot format and back.
        let mut buf = Vec::new();
        Snapshot::new(&state).save(&mut buf).unwrap();
        let state: VhostUserBlockState = Snapshot::load(&mut buf.as_slice()).unwrap().data;

        let mut restored = VhostUserBlockImpl::<RingMockFrontend>::restore_state(
            BlockConstructorArgs { mem: mem.clone() },
            &state,
        )
        .unwrap();
        assert_eq!(restored.id, "test_drive");
        assert_eq!(restored.config_space, block.config_space);
        assert_eq!(restored.avail_features, block.avail_features);
        assert_eq!(restored.acked_features, block.acked_features);
        assert_eq!(restored.queues[0].next_avail.0, 5);
        assert!(!restored.vrings_stopped);

        // Activation hands the backend the ring at the index the snapshot stopped it.
        restored
            .activate(mem, crate::devices::virtio::test_utils::default_interrupt())
            .unwrap();
        assert_eq!(unsafe { *restored.vu_handle.vu.base.get() }, 5);
    }

    #[test]
    fn test_restore_missing_features() {
        let (mut block, mem, _tmp) = activated_ring_mock();
        block.prepare_save();
        let mut state = block.save_state();
        // The snapshot's device had a feature this backend doesn't offer.
        state.virtio_state.avail_features |= 1 << 63;
        let err = VhostUserBlockImpl::<RingMockFrontend>::restore_state(
            BlockConstructorArgs { mem },
            &state,
        )
        .unwrap_err();
        assert!(matches!(err, VhostUserBlockError::RestoreFeatures { .. }));
    }
}
