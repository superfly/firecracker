// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::vhost_user::persist::VhostUserBlockState;
use super::virtio::persist::VirtioBlockState;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::vstate::memory::GuestMemoryMmap;

/// Block device state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockState {
    Virtio(VirtioBlockState),
    VhostUser(VhostUserBlockState),
}

impl BlockState {
    /// Whether the device is served by a vhost-user backend.
    pub fn is_vhost_user(&self) -> bool {
        matches!(self, BlockState::VhostUser(_))
    }

    pub fn is_activated(&self) -> bool {
        match self {
            BlockState::Virtio(virtio_block_state) => virtio_block_state.virtio_state.activated,
            BlockState::VhostUser(vhost_user_block_state) => {
                vhost_user_block_state.virtio_state.activated
            }
        }
    }
}

/// Auxiliary structure for creating a device when resuming from a snapshot.
#[derive(Debug)]
pub struct BlockConstructorArgs {
    pub mem: GuestMemoryMmap,
}
