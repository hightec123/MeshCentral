//! Operator-selectable routes declared in private server state.
use crate::{identity::decode_hex, remote::Kind, storage};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::Ipv4Addr, num::NonZeroU16, path::Path};

pub(crate) const FILE_NAME: &str = "forward-routes.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ForwardRoute {
    pub name: String,
    #[serde(skip_serializing)]
    pub group_id: String,
    pub kind: Kind,
    pub address: Ipv4Addr,
    pub port: NonZeroU16,
}

pub(crate) fn load(directory: &Path) -> Result<Vec<ForwardRoute>> {
    let path = directory.join(FILE_NAME);
    if !path.try_exists()? {
        return Ok(vec![]);
    }
    let mut routes: Vec<ForwardRoute> = storage::read_json(&path)?;
    ensure!(routes.len() <= 128, "too many forwarding routes");
    let mut names = BTreeSet::new();
    for route in &mut routes {
        decode_hex::<48>(&route.group_id)?;
        route.group_id.make_ascii_lowercase();
        ensure!(
            !route.name.is_empty()
                && route.name.len() <= 64
                && route
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "invalid forwarding route name"
        );
        ensure!(
            names.insert((route.group_id.clone(), route.name.clone())),
            "duplicate forwarding route"
        );
        ensure!(
            matches!(route.kind, Kind::Tcp | Kind::Udp),
            "invalid forwarding route protocol"
        );
        ensure!(
            route.address.is_private(),
            "forwarding route needs a private IPv4 address"
        );
    }
    Ok(routes)
}

impl ForwardRoute {
    pub fn in_group(&self, group: &str) -> bool {
        self.group_id.eq_ignore_ascii_case(group)
    }
}
