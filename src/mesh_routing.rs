use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::mesh_overlay::{MeshAddress, MeshRoute, MAX_MESH_HOPS};

pub const MESH_LINK_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/LINK/V1\0";
pub const MESH_LINK_SET_DOMAIN: &[u8] = b"SYNERGY/PQ-MESH/LINK-SET/V1\0";
pub const MAX_MESH_LINKS: usize = 16_384;
pub const MAX_LINK_COST: u32 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshLinkAdvertisement {
    pub from: MeshAddress,
    pub to: MeshAddress,
    pub epoch: u64,
    pub sequence: u64,
    pub expires_at: u64,
    pub cost: u32,
    pub capacity_kbps: u64,
    pub pq_authorization_root: [u8; 32],
}

impl MeshLinkAdvertisement {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.from == self.to {
            return Err("mesh link self-loop forbidden");
        }
        if self.epoch == 0 || self.sequence == 0 || self.expires_at == 0 {
            return Err("mesh link epoch/sequence/expiry required");
        }
        if self.cost == 0 || self.cost > MAX_LINK_COST || self.capacity_kbps == 0 {
            return Err("invalid mesh link metrics");
        }
        if self.pq_authorization_root == [0; 32] {
            return Err("mesh link PQ authorization root required");
        }
        Ok(())
    }

    pub fn live(&self, now: u64) -> bool {
        now > 0 && now <= self.expires_at && self.validate().is_ok()
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(MESH_LINK_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.from.0);
        h.update(self.to.0);
        h.update(self.epoch.to_be_bytes());
        h.update(self.sequence.to_be_bytes());
        h.update(self.expires_at.to_be_bytes());
        h.update(self.cost.to_be_bytes());
        h.update(self.capacity_kbps.to_be_bytes());
        h.update(self.pq_authorization_root);
        Some(h.finalize().into())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MeshLinkStateDb {
    links: BTreeMap<(MeshAddress, MeshAddress), MeshLinkAdvertisement>,
}

impl MeshLinkStateDb {
    pub fn upsert(&mut self, link: MeshLinkAdvertisement, now: u64) -> Result<(), &'static str> {
        link.validate()?;
        if !link.live(now) {
            return Err("stale mesh link advertisement");
        }
        let key = (link.from, link.to);
        match self.links.get(&key) {
            Some(old)
                if link.epoch < old.epoch
                    || (link.epoch == old.epoch && link.sequence <= old.sequence) =>
            {
                return Err("mesh link replay or downgrade");
            }
            Some(_) => {}
            None if self.links.len() >= MAX_MESH_LINKS => {
                return Err("mesh link-state capacity exceeded");
            }
            None => {}
        }
        self.links.insert(key, link);
        Ok(())
    }

    pub fn commitment(&self, epoch: u64, now: u64) -> Option<[u8; 32]> {
        if epoch == 0 {
            return None;
        }
        let mut live: Vec<&MeshLinkAdvertisement> = self
            .links
            .values()
            .filter(|link| link.epoch == epoch && link.live(now))
            .collect();
        live.sort_by_key(|link| (link.from, link.to));
        let mut h = Sha256::new();
        h.update(MESH_LINK_SET_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(epoch.to_be_bytes());
        h.update((live.len() as u64).to_be_bytes());
        for link in live {
            h.update(link.commitment()?);
        }
        Some(h.finalize().into())
    }

    pub fn route(
        &self,
        source: MeshAddress,
        destination: MeshAddress,
        epoch: u64,
        now: u64,
    ) -> Option<MeshRoute> {
        if source == destination || epoch == 0 {
            return None;
        }

        let links: Vec<&MeshLinkAdvertisement> = self
            .links
            .values()
            .filter(|l| l.epoch == epoch && l.live(now))
            .collect();

        let mut nodes = BTreeSet::new();
        nodes.insert(source);
        nodes.insert(destination);
        for link in &links {
            nodes.insert(link.from);
            nodes.insert(link.to);
        }

        let mut dist: BTreeMap<MeshAddress, u64> = nodes.iter().map(|n| (*n, u64::MAX)).collect();
        let mut prev: BTreeMap<MeshAddress, MeshAddress> = BTreeMap::new();
        let mut unvisited = nodes;
        *dist.get_mut(&source)? = 0;

        while !unvisited.is_empty() {
            let current = unvisited
                .iter()
                .min_by_key(|node| (dist.get(node).copied().unwrap_or(u64::MAX), **node))
                .copied()?;
            let current_dist = dist.get(&current).copied()?;
            if current_dist == u64::MAX {
                break;
            }
            unvisited.remove(&current);
            if current == destination {
                break;
            }

            for link in links.iter().filter(|link| link.from == current) {
                if !unvisited.contains(&link.to) {
                    continue;
                }
                let candidate = current_dist.checked_add(link.cost as u64)?;
                let old = dist.get(&link.to).copied().unwrap_or(u64::MAX);
                let should_update = candidate < old
                    || (candidate == old
                        && prev
                            .get(&link.to)
                            .is_none_or(|existing| current < *existing));
                if should_update {
                    dist.insert(link.to, candidate);
                    prev.insert(link.to, current);
                }
            }
        }

        if dist.get(&destination).copied()? == u64::MAX {
            return None;
        }

        let mut rev = vec![destination];
        let mut cur = destination;
        while cur != source {
            cur = *prev.get(&cur)?;
            rev.push(cur);
            if rev.len() > MAX_MESH_HOPS {
                return None;
            }
        }
        rev.reverse();

        let route = MeshRoute {
            source,
            destination,
            hops: rev,
            epoch,
        };
        route.validate().ok()?;
        Some(route)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: u8) -> MeshAddress {
        MeshAddress([v; 32])
    }

    fn link(from: u8, to: u8, cost: u32, seq: u64) -> MeshLinkAdvertisement {
        MeshLinkAdvertisement {
            from: a(from),
            to: a(to),
            epoch: 7,
            sequence: seq,
            expires_at: 100,
            cost,
            capacity_kbps: 100_000,
            pq_authorization_root: [from.wrapping_add(to); 32],
        }
    }

    #[test]
    fn chooses_cheapest_multi_hop_path() {
        let mut db = MeshLinkStateDb::default();
        db.upsert(link(1, 2, 2, 1), 10).unwrap();
        db.upsert(link(2, 4, 2, 1), 10).unwrap();
        db.upsert(link(1, 3, 1, 1), 10).unwrap();
        db.upsert(link(3, 4, 10, 1), 10).unwrap();
        let r = db.route(a(1), a(4), 7, 10).unwrap();
        assert_eq!(r.hops, vec![a(1), a(2), a(4)]);
    }

    #[test]
    fn replay_and_downgrade_are_rejected() {
        let mut db = MeshLinkStateDb::default();
        db.upsert(link(1, 2, 1, 2), 10).unwrap();
        assert!(db.upsert(link(1, 2, 1, 2), 10).is_err());
        assert!(db.upsert(link(1, 2, 1, 1), 10).is_err());
    }

    #[test]
    fn expired_link_disappears_from_route() {
        let mut db = MeshLinkStateDb::default();
        db.upsert(link(1, 2, 1, 1), 10).unwrap();
        db.upsert(link(2, 3, 1, 1), 10).unwrap();
        assert!(db.route(a(1), a(3), 7, 10).is_some());
        assert!(db.route(a(1), a(3), 7, 101).is_none());
    }

    #[test]
    fn deterministic_tie_break_is_stable() {
        let mut db = MeshLinkStateDb::default();
        for l in [
            link(1, 2, 1, 1),
            link(2, 4, 1, 1),
            link(1, 3, 1, 1),
            link(3, 4, 1, 1),
        ] {
            db.upsert(l, 10).unwrap();
        }
        let r = db.route(a(1), a(4), 7, 10).unwrap();
        assert_eq!(r.hops, vec![a(1), a(2), a(4)]);
    }
}
