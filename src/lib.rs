#![deny(missing_docs)]
//! # IPTable
//!
//! This crate contains an efficient data structure for storing and querying values by CIDR.
//!
//! # Examples
//! ```
//! use iptable::Ipv4Table;
//! use ipnetwork::Ipv4Network;
//!
//! let mut table = Ipv4Table::new();
//! table.insert("192.168.2.0/24".parse::<Ipv4Network>().unwrap(), 42);
//! table.insert("192.168.1.0/24".parse::<Ipv4Network>().unwrap(), 43);
//!
//! assert_eq!(table.get("192.168.2.0/24".parse::<Ipv4Network>().unwrap()), Some(&42));
//!
//! // Iterate over the prefixes under a given prefix
//! let ipnet: Ipv4Network = "192.168.0.0/16".parse().unwrap();
//! let relevant = table.iter_prefix(ipnet).collect::<Vec<_>>();
//! assert_eq!(2, relevant.len());
//!
//! // Merge entries with longer prefixes
//! let merged_table = table.merge_longer_prefixes(16, |a, b| a + b);
//! assert_eq!(
//!     merged_table.iter().collect::<Vec<_>>(),
//!     vec![(&"192.168.0.0/16".parse().unwrap(), &85)]
//! );
//! ```

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A trait for types that can be used as subnets.
pub trait Subnet: PartialOrd + Ord + PartialEq + Copy + std::fmt::Debug {
    /// Get the prefix length of the subnet.
    fn prefix(self) -> u8;

    /// Get the last address in the subnet.
    fn last(self) -> Self;

    /// Check if the subnet is a subnet of another subnet.
    fn is_subnet_of(self, other: Self) -> bool;

    /// Create a new subnet that is a copy of this one with a different prefix.
    ///
    /// The host bits are set to 0.
    fn with_prefix(self, prefix: u8) -> Self;
}

impl Subnet for Ipv4Network {
    fn prefix(self) -> u8 {
        Ipv4Network::prefix(self)
    }
    fn last(self) -> Self {
        let mut last = self.ip().to_bits();
        for i in 0..32 - self.prefix() {
            last |= 1 << i;
        }
        Ipv4Network::new(Ipv4Addr::from_bits(last), self.prefix()).unwrap()
    }

    fn is_subnet_of(self, other: Self) -> bool {
        Ipv4Network::is_subnet_of(self, other)
    }

    fn with_prefix(self, prefix: u8) -> Self {
        assert!(prefix <= 32);
        let mut ip = self.ip().to_bits();
        for i in prefix..32 {
            // Clear the bit at index i
            ip &= !(1 << (31 - i));
        }
        Self::new(Ipv4Addr::from_bits(ip), prefix).unwrap()
    }
}

impl Subnet for Ipv6Network {
    fn prefix(self) -> u8 {
        Ipv6Network::prefix(&self)
    }
    fn last(self) -> Self {
        let mut last = self.ip().to_bits();
        for i in 0..128 - self.prefix() {
            last |= 1 << i;
        }
        Ipv6Network::new(Ipv6Addr::from_bits(last), self.prefix()).unwrap()
    }

    fn is_subnet_of(self, other: Self) -> bool {
        Ipv6Network::is_subnet_of(self, other)
    }

    fn with_prefix(self, prefix: u8) -> Self {
        assert!(prefix <= 128);
        let mut ip = self.ip().to_bits();
        for i in prefix..128 {
            // Clear the bit at index i
            ip &= !(1 << (127 - i));
        }
        Self::new(Ipv6Addr::from_bits(ip), prefix).unwrap()
    }
}

impl Subnet for IpNetwork {
    fn prefix(self) -> u8 {
        match self {
            IpNetwork::V4(net) => net.prefix(),
            IpNetwork::V6(net) => net.prefix(),
        }
    }
    fn last(self) -> Self {
        match self {
            IpNetwork::V4(net) => IpNetwork::V4(net.last()),
            IpNetwork::V6(net) => IpNetwork::V6(net.last()),
        }
    }

    fn is_subnet_of(self, other: Self) -> bool {
        match (self, other) {
            (IpNetwork::V4(net1), IpNetwork::V4(net2)) => net1.is_subnet_of(net2),
            (IpNetwork::V6(net1), IpNetwork::V6(net2)) => net1.is_subnet_of(net2),
            _ => false,
        }
    }

    fn with_prefix(self, prefix: u8) -> Self {
        match self {
            IpNetwork::V4(net) => IpNetwork::V4(net.with_prefix(prefix)),
            IpNetwork::V6(net) => IpNetwork::V6(net.with_prefix(prefix)),
        }
    }
}

/// Base structure for storing values by CIDR.
pub struct IpTable<N: Subnet, T>(BTreeMap<N, T>);

/// A table for storing values by IPv4 or IPv6 CIDR.
pub type UniversalIpTable<T> = IpTable<IpNetwork, T>;

/// A table for storing values by IPv4 CIDR.
pub type Ipv4Table<T> = IpTable<Ipv4Network, T>;

/// A table for storing values by IPv6 CIDR.
pub type Ipv6Table<T> = IpTable<Ipv6Network, T>;

impl Default for UniversalIpTable<u32> {
    fn default() -> Self {
        UniversalIpTable::new()
    }
}

impl<N: Subnet, T> IntoIterator for IpTable<N, T> {
    type Item = (N, T);
    type IntoIter = std::collections::btree_map::IntoIter<N, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<N: Subnet, T> IpTable<N, T> {
    /// Create a new table.
    pub fn new() -> Self {
        IpTable(BTreeMap::new())
    }

    /// Returns the number of elements in the table.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Insert a value into the table.
    pub fn insert(&mut self, net: N, value: T) {
        self.0.insert(net, value);
    }

    /// Get a value from the table.
    pub fn get<S: Into<N>>(&self, net: S) -> Option<&T> {
        self.0.get(&net.into())
    }

    /// Remove a value from the table.
    pub fn remove<S: Into<N>>(&mut self, net: S) -> Option<T> {
        self.0.remove(&net.into())
    }

    /// Get the entry for the given network.
    pub fn entry(&mut self, net: N) -> std::collections::btree_map::Entry<N, T> {
        self.0.entry(net)
    }

    /// Iterate over the entries in the table.
    pub fn iter(&self) -> impl Iterator<Item = (&N, &T)> {
        self.0.iter()
    }

    /// Iterate over the prefixes under the given prefix.
    pub fn iter_prefix<S: Into<N>>(&self, prefix: S) -> impl Iterator<Item = (&N, &T)> {
        let prefix: N = prefix.into();

        self.0
            .range(prefix..prefix.last())
            .filter(move |(net, _)| net.is_subnet_of(prefix))
    }

    /// Merge entries with longer prefixes into the target prefix.
    pub fn merge_longer_prefixes(self, target_prefix: u8, merge_fn: impl Fn(T, T) -> T) -> Self {
        let mut new_table = Self::new();

        for (net, value) in self.0.into_iter() {
            if net.prefix() >= target_prefix {
                let net = net.with_prefix(target_prefix);

                // If the entry already exists, merge the values
                if let Some(existing_value) = new_table.remove(net) {
                    new_table.insert(net, merge_fn(existing_value, value));
                } else {
                    new_table.insert(net, value);
                }
            } else {
                new_table.insert(net, value);
            }
        }

        new_table
    }

    /// Get the value for the closest ancestor of the given network.
    pub fn get_containing_prefix<S: Into<N>>(&self, net: S) -> Option<(N, &T)> {
        let net: N = net.into();
        self.iter_containing_prefixes(net).next()
    }

    /// Iterate over the shorter prefixes of the given network.
    pub fn iter_containing_prefixes<S: Into<N>>(&self, net: S) -> impl Iterator<Item = (N, &T)> {
        let net: N = net.into();
        (0..net.prefix()).rev().filter_map(move |i| {
            let parent = net.with_prefix(i);
            self.get(parent).map(|value| (parent, value))
        })
    }
}

impl<N: Subnet, T: std::fmt::Debug> std::fmt::Debug for IpTable<N, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.0.iter()).finish()
    }
}

mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_simple() {
        let mut table = IpTable::new();

        let net: IpNetwork = "192.168.0.0/24".parse().unwrap();

        table.insert(net, 42);

        assert_eq!(table.get(net), Some(&42));

        table.remove(net);

        assert_eq!(table.get(net), None);
    }

    #[test]
    fn test_iter_prefix() {
        let mut table = UniversalIpTable::new();

        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let ip1: IpAddr = "192.168.2.1".parse().unwrap();
        let ip2: IpAddr = "192.168.3.3".parse().unwrap();
        let net1: IpNetwork = "192.168.4.0/24".parse().unwrap();
        let net2: IpNetwork = "192.168.5.0/24".parse().unwrap();
        let net3: IpNetwork = "10.1.2.3/32".parse().unwrap();

        table.insert(ip1.into(), 1);
        table.insert(ip2.into(), 2);
        table.insert(net1, 42);
        table.insert(net2, 43);
        table.insert(net3, 44);

        assert!(!table.is_empty());
        assert_eq!(table.len(), 5);

        let ipnet: IpNetwork = "192.168.0.0/16".parse().unwrap();

        let relevant = table.iter_prefix(ipnet).collect::<Vec<_>>();
        assert_eq!(
            relevant,
            vec![
                (&ip1.into(), &1),
                (&ip2.into(), &2),
                (&net1, &42),
                (&net2, &43),
            ]
        );

        assert_eq!(table.remove(ip1), Some(1));
    }

    #[test]
    fn test_merge_longer_prefixes() {
        let mut table = UniversalIpTable::new();

        let net1: IpNetwork = "192.168.2.0/24".parse().unwrap();
        let net2: IpNetwork = "192.168.2.64/26".parse().unwrap();

        table.insert(net1, 42);
        table.insert(net2, 43);

        let merged_table = table.merge_longer_prefixes(16, |a, b| a + b);

        assert_eq!(
            merged_table.iter().collect::<Vec<_>>(),
            vec![(&"192.168.0.0/16".parse().unwrap(), &85)]
        );
    }

    #[test]
    fn test_get_ancestor() {
        let mut table = UniversalIpTable::new();

        let net1: IpNetwork = "192.168.0.0/16".parse().unwrap();

        table.insert(net1, 42);
        let ip1: IpAddr = "192.168.2.1".parse().unwrap();
        assert_eq!(table.get_containing_prefix(ip1).unwrap(), (net1, &42));
    }
}
