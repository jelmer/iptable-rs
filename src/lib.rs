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
//! // Find unassigned /20s in the table
//! let unassigned = table.gaps(
//!     "192.168.0.0/18".parse::<Ipv4Network>().unwrap(), Some(20))
//!     .collect::<Vec<_>>();
//!
//! assert_eq!(
//!    unassigned, vec![
//!        "192.168.16.0/20".parse().unwrap(),
//!        "192.168.32.0/19".parse().unwrap()]);
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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A trait for types that can be used as subnets.
pub trait Subnet: PartialOrd + Ord + PartialEq + Copy + std::fmt::Debug + std::hash::Hash {
    /// The address type for the subnet.
    type Address: Copy + std::fmt::Debug;

    /// Get the prefix length of the subnet.
    fn prefix(self) -> u8;

    /// Get the last address in the subnet.
    fn last(self) -> Self;

    /// Check if the subnet is a subnet of another subnet.
    fn is_subnet_of(self, other: Self) -> bool;

    /// Create a new subnet that is a copy of this one with a different prefix.
    ///
    /// The host bits are set to 0.
    fn with_prefix_len(self, prefix: u8) -> Self;

    /// Toggle the bit at the given index.
    fn toggle_bit(self, index: u8) -> Self;

    /// Address size in bits.
    fn addr_size(self) -> u8;

    /// Get the host address of the subnet.
    fn network(self) -> Self::Address;
}

impl Subnet for Ipv4Network {
    type Address = Ipv4Addr;

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

    fn with_prefix_len(self, prefix: u8) -> Self {
        assert!(prefix <= 32);
        let mut ip = self.ip().to_bits();
        for i in prefix..32 {
            // Clear the bit at index i
            ip &= !(1 << (31 - i));
        }
        Self::new(Ipv4Addr::from_bits(ip), prefix).unwrap()
    }

    fn toggle_bit(self, index: u8) -> Self {
        let mut ip = self.ip().to_bits();
        ip ^= 1 << (31 - index);
        Self::new(Ipv4Addr::from_bits(ip), self.prefix()).unwrap()
    }

    fn addr_size(self) -> u8 {
        32
    }

    fn network(self) -> Ipv4Addr {
        Ipv4Network::network(&self)
    }
}

impl Subnet for Ipv6Network {
    type Address = Ipv6Addr;

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

    fn with_prefix_len(self, prefix: u8) -> Self {
        assert!(prefix <= 128);
        let mut ip = self.ip().to_bits();
        for i in prefix..128 {
            // Clear the bit at index i
            ip &= !(1 << (127 - i));
        }
        Self::new(Ipv6Addr::from_bits(ip), prefix).unwrap()
    }

    fn toggle_bit(self, index: u8) -> Self {
        let mut ip = self.ip().to_bits();
        ip ^= 1 << (127 - index);
        Self::new(Ipv6Addr::from_bits(ip), self.prefix()).unwrap()
    }

    fn addr_size(self) -> u8 {
        128
    }

    fn network(self) -> Ipv6Addr {
        Ipv6Network::network(&self)
    }
}

impl Subnet for IpNetwork {
    type Address = IpAddr;

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

    fn with_prefix_len(self, prefix: u8) -> Self {
        match self {
            IpNetwork::V4(net) => IpNetwork::V4(net.with_prefix_len(prefix)),
            IpNetwork::V6(net) => IpNetwork::V6(net.with_prefix_len(prefix)),
        }
    }

    fn toggle_bit(self, index: u8) -> Self {
        match self {
            IpNetwork::V4(net) => IpNetwork::V4(net.toggle_bit(index)),
            IpNetwork::V6(net) => IpNetwork::V6(net.toggle_bit(index)),
        }
    }

    fn addr_size(self) -> u8 {
        match self {
            IpNetwork::V4(_) => 32,
            IpNetwork::V6(_) => 128,
        }
    }

    fn network(self) -> IpAddr {
        match self {
            IpNetwork::V4(net) => IpAddr::V4(net.network()),
            IpNetwork::V6(net) => IpAddr::V6(net.network()),
        }
    }
}

/// Base structure for storing values by CIDR.
pub struct GenericIpTable<N: Subnet, T>(BTreeMap<N, T>);

/// A table for storing values by IPv4 or IPv6 CIDR.
pub type IpTable<T> = GenericIpTable<IpNetwork, T>;

/// Alias for IpTable
pub type UniversalIpTable<T> = IpTable<T>;

/// A table for storing values by IPv4 CIDR.
pub type Ipv4Table<T> = GenericIpTable<Ipv4Network, T>;

/// A table for storing values by IPv6 CIDR.
pub type Ipv6Table<T> = GenericIpTable<Ipv6Network, T>;

impl<T> Default for IpTable<T> {
    fn default() -> Self {
        IpTable::new()
    }
}

impl<N: Subnet, T> IntoIterator for GenericIpTable<N, T> {
    type Item = (N, T);
    type IntoIter = std::collections::btree_map::IntoIter<N, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<N: Subnet, T> FromIterator<(N, T)> for GenericIpTable<N, T> {
    fn from_iter<I: IntoIterator<Item = (N, T)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<N: Subnet, T> GenericIpTable<N, T> {
    /// Create a new table.
    pub fn new() -> Self {
        Self(BTreeMap::new())
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
    pub fn insert<S: Into<N>>(&mut self, net: S, value: T) {
        let net: N = net.into();
        self.0.insert(net, value);
    }

    /// Get a value from the table.
    ///
    /// Exact match only.
    pub fn get<S: Into<N>>(&self, net: S) -> Option<&T> {
        self.0.get(&net.into())
    }

    /// Get a mutable reference to a value in the table.
    ///
    /// Exact match only.
    pub fn get_mut<S: Into<N>>(&mut self, net: S) -> Option<&mut T> {
        self.0.get_mut(&net.into())
    }

    /// Remove a value from the table.
    pub fn remove<S: Into<N>>(&mut self, net: S) -> Option<T> {
        self.0.remove(&net.into())
    }

    /// Get the entry for the given network.
    pub fn entry(&mut self, net: N) -> std::collections::btree_map::Entry<'_, N, T> {
        self.0.entry(net)
    }

    /// Iterate over the entries in the table, ordered by prefix.
    pub fn iter(&self) -> impl Iterator<Item = (&N, &T)> {
        self.0.iter()
    }

    /// Iterate over the prefixes under the given prefix, including the prefix itself.
    pub fn iter_prefix<S: Into<N>>(&self, prefix: S) -> impl Iterator<Item = (&N, &T)> {
        let prefix: N = prefix.into();

        self.0
            .range(prefix..prefix.last())
            .filter(move |(net, _)| net.is_subnet_of(prefix))
    }

    /// Iterate over the prefixes under the given prefix, excluding the prefix itself.
    pub fn iter_subprefixes<S: Into<N>>(&self, prefix: S) -> impl Iterator<Item = (&N, &T)> {
        let prefix: N = prefix.into();

        self.0
            .range(prefix.with_prefix_len(prefix.prefix() + 1)..prefix.last())
            .filter(move |(net, _)| net.is_subnet_of(prefix))
    }

    /// Merge entries with longer prefixes into the target prefix.
    pub fn merge_longer_prefixes(self, target_prefix: u8, merge_fn: impl Fn(T, T) -> T) -> Self {
        let mut new_table = Self::new();

        for (net, value) in self.0.into_iter() {
            if net.prefix() >= target_prefix {
                let net = net.with_prefix_len(target_prefix);

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

    /// Get the value for the longest prefix that contains the given network.
    ///
    /// # Example
    /// ```
    /// use iptable::IpTable;
    /// use ipnetwork::IpNetwork;
    /// let mut table = IpTable::new();
    /// table.insert("192.168.2.0/24".parse::<IpNetwork>().unwrap(), 42);
    /// let ip1: std::net::IpAddr = "192.168.2.4".parse().unwrap();
    /// assert_eq!(
    ///     table.get_containing_prefix(ip1),
    ///     Some(("192.168.2.0/24".parse().unwrap(), &42)));
    /// ```
    pub fn get_containing_prefix<S: Into<N>>(&self, net: S) -> Option<(N, &T)> {
        let net: N = net.into();
        self.iter_containing_prefixes(net).next()
    }

    /// Iterate over the shorter prefixes of the given network, longest first.
    pub fn iter_containing_prefixes<S: Into<N>>(&self, net: S) -> impl Iterator<Item = (N, &T)> {
        let net: N = net.into();
        (0..net.prefix()).rev().filter_map(move |i| {
            let parent = net.with_prefix_len(i);
            self.get(parent).map(|value| (parent, value))
        })
    }

    /// Update the table with the given iterator.
    pub fn update<I: IntoIterator<Item = (N, T)>>(&mut self, iter: I) {
        for (net, value) in iter {
            self.insert(net, value);
        }
    }

    /// Iterate over the gaps in the table.
    ///
    /// This will yield the prefixes that are not in the table. The shortest prefixes
    /// will be yielded first.
    ///
    /// # Arguments
    /// * `prefix` - The prefix under which to find gaps
    /// * `max_prefix` - The maximum prefix length to yield
    ///
    /// # Example
    /// ```
    /// use iptable::IpTable;
    /// use ipnetwork::IpNetwork;
    /// let mut table = IpTable::new();
    /// table.insert("192.168.2.0/24".parse::<IpNetwork>().unwrap(), 42);
    /// table.insert("192.168.2.128/25".parse::<IpNetwork>().unwrap(), 43);
    ///
    /// let gaps = table.gaps("192.168.0.0/18".parse::<IpNetwork>().unwrap(), Some(20))
    ///    .collect::<Vec<_>>();
    /// assert_eq!(
    ///     gaps, vec![
    ///         "192.168.16.0/20".parse().unwrap(),
    ///         "192.168.32.0/19".parse().unwrap()]);
    /// ```
    pub fn gaps<S: Into<N>>(
        &self,
        prefix: S,
        max_prefix: Option<u8>,
    ) -> impl Iterator<Item = N> + '_ {
        let prefix: N = prefix.into();

        let mut todo = std::iter::once(prefix).collect::<std::collections::BTreeSet<_>>();
        // for each side, check if it is in the table
        // if it has some children in the table, add it to the todo list
        // if it has no children in the table, yield it
        std::iter::from_fn(move || {
            while let Some(prefix) = todo.pop_first() {
                // If the prefix nor any children are in the table, yield it
                if self.iter_prefix(prefix).next().is_none() {
                    return Some(prefix);
                }

                if prefix.prefix() + 1 > max_prefix.unwrap_or(u8::MAX) {
                    continue;
                }

                let a = prefix.with_prefix_len(prefix.prefix() + 1);
                let b = prefix
                    .toggle_bit(prefix.prefix())
                    .with_prefix_len(prefix.prefix() + 1);

                if !self.contains(b) {
                    todo.insert(b);
                }

                if !self.contains(a) {
                    todo.insert(a);
                }
            }
            None
        })
    }

    /// Check if the table contains the given network.
    pub fn contains<S: Into<N>>(&self, net: S) -> bool {
        let net: N = net.into();
        self.0.contains_key(&net)
    }

    /// Return values for all the prefixes in the table.
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    /// Retain only the entries that satisfy the predicate.
    pub fn retain<F: FnMut(&N, &T) -> bool>(&mut self, mut f: F) {
        self.0.retain(|k, v| f(k, v));
    }

    /// Iterate over all gaps with a specific prefix length.
    pub fn gaps_with_prefix_len(&self, prefix: N, prefix_len: u8) -> impl Iterator<Item = N> + '_ {
        let prefix: N = prefix;

        let mut todo = std::iter::once(prefix).collect::<std::collections::BTreeSet<_>>();
        // for each side, check if it is in the table
        // if it has some children in the table, add it to the todo list
        // if it has no children in the table, yield it
        std::iter::from_fn(move || {
            while let Some(prefix) = todo.pop_first() {
                // If the prefix is the right length, then we can either yield it
                // or skip it if it exists or has children
                if prefix.prefix() == prefix_len {
                    if self.iter_prefix(prefix).next().is_none() {
                        return Some(prefix);
                    }
                    continue;
                }

                assert!(prefix.prefix() < prefix_len);

                let a = prefix.with_prefix_len(prefix.prefix() + 1);
                let b = prefix
                    .toggle_bit(prefix.prefix())
                    .with_prefix_len(prefix.prefix() + 1);

                if !self.contains(b) {
                    todo.insert(b);
                }

                if !self.contains(a) {
                    todo.insert(a);
                }
            }
            None
        })
    }

    /// Find all unassigned IPs in the given prefix.
    pub fn gap_ips_in_prefix(&self, prefix: N) -> impl Iterator<Item = N::Address> + '_ {
        self.gaps_with_prefix_len(prefix, prefix.addr_size())
            .map(|net| net.network())
    }

    fn _iter_occupied(&self, prefixes: impl Iterator<Item = N>) -> impl Iterator<Item = N> + '_ {
        // iterate over all the prefix lengths, longest to shortest
        // for each prefix length, iterate over all the prefixes with that length

        let mut by_len: std::collections::HashMap<u8, std::collections::HashSet<N>> =
            std::collections::HashMap::new();
        for net in prefixes {
            by_len.entry(net.prefix()).or_default().insert(net);
        }

        let by_len = std::rc::Rc::new(std::cell::RefCell::new(by_len));

        (0..=128).rev().flat_map(move |l| {
            let by_len = by_len.clone();
            let prefixes = by_len.borrow_mut().remove(&l).unwrap_or_default();

            prefixes.clone().into_iter().filter(move |prefix| {
                let by_len = by_len.clone();
                // find the toggled prefix
                let toggled = prefix.toggle_bit(prefix.prefix() - 1);
                // if the toggled prefix is in the table, then add the parent prefix to the
                // list
                if !prefixes.contains(&toggled) {
                    true
                } else {
                    by_len
                        .borrow_mut()
                        .entry(prefix.prefix() - 1)
                        .or_default()
                        .insert(prefix.with_prefix_len(prefix.prefix() - 1));
                    false
                }
            })
        })
    }

    /// Iterate over the non-overlapping occupied prefixes in the table.
    ///
    /// This will merge adjacent prefixes as much as possible.
    pub fn iter_occupied(&self) -> impl Iterator<Item = N> + '_ {
        self._iter_occupied(self.0.keys().copied())
    }

    /// Iterate over the occupied prefixes in the table under a given prefix.
    ///
    /// This will yield the prefixes in order of length, longest first.
    pub fn iter_occupied_prefix(&self, prefix: N) -> impl Iterator<Item = N> + '_ {
        self._iter_occupied(self.iter_prefix(prefix).map(|(net, _)| *net))
    }
}

/// Find all gaps in prefix before the given child prefix.
///
/// E.g.:
/// If parent is 192.168.2.0/24, and child is 192.168.2.196/26
///
/// Then this will yield:
/// 192.168.2.128/26
/// 192.168.2.0/25
///
/// This will yield the shortest prefixes first.
///
/// # Arguments
/// * `prefix` - The parent prefix
/// * `child` - The child prefix
/// * `max_prefix` - The maximum prefix length to yield
pub fn surrounding_gaps<N: Subnet>(
    mut prefix: N,
    child: N,
    max_prefix: Option<u8>,
) -> impl Iterator<Item = N> {
    // Produce all subprefixes of the parent prefix
    // 192.168.2.0/24 => overlaps
    // 192.168.2.128/25 =>
    // 192.168.2.128/26
    let child = child.with_prefix_len(child.prefix());
    let max_prefix = if let Some(max_prefix) = max_prefix {
        std::cmp::min(max_prefix, child.prefix())
    } else {
        child.prefix()
    };
    (prefix.prefix() + 1..=max_prefix).flat_map(move |i| {
        let a = prefix.with_prefix_len(i);
        let b = prefix.toggle_bit(i - 1).with_prefix_len(i);

        if child.is_subnet_of(a) {
            prefix = a;
            Some(b)
        } else if child.is_subnet_of(b) {
            prefix = b;
            Some(a)
        } else if prefix.prefix() + 1 == i {
            Some(prefix)
        } else {
            None
        }
    })
}

/// Iterate over all prefixes with the given prefix length.
pub fn exact_prefixes<N: Subnet>(prefix: N, prefix_len: u8) -> impl Iterator<Item = N> {
    let mut todo = std::collections::VecDeque::<N>::new();
    todo.push_back(prefix);
    std::iter::from_fn(move || {
        while let Some(prefix) = todo.pop_front() {
            if prefix.prefix() == prefix_len {
                return Some(prefix);
            }

            let a = prefix.with_prefix_len(prefix.prefix() + 1);
            let b = prefix
                .toggle_bit(prefix.prefix())
                .with_prefix_len(prefix.prefix() + 1);

            assert_ne!(a, b);

            todo.push_front(b);
            todo.push_front(a);
        }
        None
    })
}

impl<N: Subnet, T: std::fmt::Debug> std::fmt::Debug for GenericIpTable<N, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.0.iter()).finish()
    }
}

impl<N: Subnet, T: Clone> Clone for GenericIpTable<N, T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<N: Subnet, T: PartialEq> PartialEq for GenericIpTable<N, T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<N: Subnet, T: Eq> Eq for GenericIpTable<N, T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_simple() {
        let mut table = GenericIpTable::<IpNetwork, u32>::new();

        let net: IpNetwork = "192.168.0.0/24".parse().unwrap();

        table.insert(net, 42);

        assert_eq!(table.get(net), Some(&42));

        table.remove(net);

        assert_eq!(table.get(net), None);
    }

    #[test]
    fn test_iter_prefix() {
        let mut table = IpTable::new();

        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let ip1: IpAddr = "192.168.2.1".parse().unwrap();
        let ip2: IpAddr = "192.168.3.3".parse().unwrap();
        let net1: IpNetwork = "192.168.4.0/24".parse().unwrap();
        let net2: IpNetwork = "192.168.5.0/24".parse().unwrap();
        let net3: IpNetwork = "10.1.2.3/32".parse().unwrap();

        table.insert(ip1, 1);
        table.insert(ip2, 2);
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
        let mut table = IpTable::new();

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
        let mut table = IpTable::new();

        let net1: IpNetwork = "192.168.0.0/16".parse().unwrap();

        table.insert(net1, 42);
        let ip1: IpAddr = "192.168.2.1".parse().unwrap();
        assert_eq!(table.get_containing_prefix(ip1).unwrap(), (net1, &42));
    }

    #[test]
    fn test_surrounding_gaps() {
        let parent: IpNetwork = "192.168.2.0/24".parse().unwrap();
        let child: IpNetwork = "192.168.2.196/26".parse().unwrap();

        let gaps = surrounding_gaps(parent, child, None).collect::<Vec<_>>();
        assert_eq!(
            gaps,
            vec![
                "192.168.2.0/25".parse().unwrap(),
                "192.168.2.128/26".parse().unwrap()
            ]
        );

        let parent: IpNetwork = "192.168.2.0/24".parse().unwrap();
        let child: IpNetwork = "192.168.2.0/25".parse().unwrap();
        let gaps = surrounding_gaps(parent, child, None).collect::<Vec<_>>();
        assert_eq!(gaps, vec!["192.168.2.128/25".parse().unwrap(),]);

        let parent: IpNetwork = "192.168.2.0/24".parse().unwrap();
        let child: IpNetwork = "192.168.2.0/24".parse().unwrap();
        let gaps = surrounding_gaps(parent, child, None).collect::<Vec<_>>();
        assert_eq!(gaps, vec![]);

        let parent: IpNetwork = "192.168.2.0/24".parse().unwrap();
        let child: IpNetwork = "192.168.2.132".parse().unwrap();
        let gaps = surrounding_gaps(parent, child, None).collect::<Vec<_>>();
        assert_eq!(
            gaps,
            vec![
                // 192.168.2.0-192.168.2.128
                "192.168.2.0/25".parse().unwrap(),
                "192.168.2.192/26".parse().unwrap(),
                "192.168.2.160/27".parse().unwrap(),
                "192.168.2.144/28".parse().unwrap(),
                "192.168.2.136/29".parse().unwrap(),
                "192.168.2.128/30".parse().unwrap(),
                "192.168.2.134/31".parse().unwrap(),
                "192.168.2.133/32".parse().unwrap(),
            ]
        );

        let gaps = surrounding_gaps(parent, child, Some(26)).collect::<Vec<_>>();
        assert_eq!(
            gaps,
            vec![
                "192.168.2.0/25".parse().unwrap(),
                "192.168.2.192/26".parse().unwrap(),
            ]
        );

        // Child is unrelated
        let parent: IpNetwork = "192.168.2.0/24".parse().unwrap();
        let child: IpNetwork = "192.168.3.0/26".parse().unwrap();

        let gaps = surrounding_gaps(parent, child, None).collect::<Vec<_>>();
        assert_eq!(gaps, vec!["192.168.2.0/24".parse().unwrap(),]);
    }

    #[test]
    fn test_gaps() {
        let mut table = IpTable::new();

        let net1: IpNetwork = "192.168.2.0/24".parse().unwrap();
        let net2: IpNetwork = "192.168.2.64/26".parse().unwrap();

        table.insert(net1, 42);
        table.insert(net2, 43);

        let gaps = table.gaps(net1, None).collect::<Vec<_>>();

        assert_eq!(
            gaps,
            vec![
                "192.168.2.0/26".parse().unwrap(),
                "192.168.2.128/25".parse().unwrap(),
            ]
        );

        let mut filled = table.clone();
        filled.update(gaps.into_iter().map(|net| (net, 0)));
        assert_eq!(filled.gaps(net1, None).collect::<Vec<_>>(), vec![]);

        let gaps = table.gaps(net1, Some(25)).collect::<Vec<_>>();

        assert_eq!(gaps, vec!["192.168.2.128/25".parse().unwrap(),]);

        let mut filled = table.clone();
        filled.update(gaps.into_iter().map(|net| (net, 0)));
        assert_eq!(filled.gaps(net1, Some(25)).collect::<Vec<_>>(), vec![]);

        let gaps = table.gaps(net1, Some(24)).collect::<Vec<_>>();
        assert_eq!(gaps, vec![]);
    }

    #[test]
    fn test_exact_prefixes() {
        let net: IpNetwork = "192.168.2.0/24".parse().unwrap();

        let prefixes = exact_prefixes(net, 24).collect::<Vec<_>>();
        assert_eq!(prefixes, vec![net]);

        let prefixes = exact_prefixes(net, 25).collect::<Vec<_>>();
        assert_eq!(
            prefixes,
            vec![
                "192.168.2.0/25".parse().unwrap(),
                "192.168.2.128/25".parse().unwrap()
            ]
        );

        let prefixes = exact_prefixes(net, 26).collect::<Vec<_>>();
        assert_eq!(
            prefixes,
            vec![
                "192.168.2.0/26".parse().unwrap(),
                "192.168.2.64/26".parse().unwrap(),
                "192.168.2.128/26".parse().unwrap(),
                "192.168.2.192/26".parse().unwrap()
            ]
        );

        let net = "2001:db8::/64".parse::<Ipv6Network>().unwrap();
        assert_eq!(
            exact_prefixes(net, 64).collect::<Vec<_>>(),
            vec![net.clone()]
        );

        assert_eq!(
            exact_prefixes(net, 65).collect::<Vec<_>>(),
            vec![
                "2001:db8::/65".parse().unwrap(),
                "2001:db8:0:0:8000::/65".parse().unwrap()
            ]
        );

        assert_eq!(
            exact_prefixes(net, 66).collect::<Vec<_>>(),
            vec![
                "2001:db8::/66".parse().unwrap(),
                "2001:db8:0:0:4000::/66".parse().unwrap(),
                "2001:db8:0:0:8000::/66".parse().unwrap(),
                "2001:db8:0:0:c000::/66".parse().unwrap()
            ]
        );

        assert_eq!(
            exact_prefixes(net, 128).take(4).collect::<Vec<_>>(),
            vec![
                "2001:db8::/128".parse().unwrap(),
                "2001:db8::1/128".parse().unwrap(),
                "2001:db8::2/128".parse().unwrap(),
                "2001:db8::3/128".parse().unwrap()
            ]
        );
    }

    #[test]
    fn test_gaps_with_prefix_len() {
        let mut table = IpTable::new();

        let net1: IpNetwork = "192.168.2.128/25".parse().unwrap();

        table.insert(net1, 42);

        let net: IpNetwork = "192.168.2.0/24".parse().unwrap();
        assert_eq!(
            table.gaps_with_prefix_len(net, 26).collect::<Vec<_>>(),
            vec![
                "192.168.2.0/26".parse().unwrap(),
                "192.168.2.64/26".parse().unwrap()
            ]
        );

        let mut gaps = table.gaps_with_prefix_len(net, 32);
        assert_eq!(
            "192.168.2.0/32".parse::<IpNetwork>().unwrap(),
            gaps.next().unwrap()
        );
        assert_eq!(
            "192.168.2.1/32".parse::<IpNetwork>().unwrap(),
            gaps.next().unwrap()
        );
        assert_eq!(
            "192.168.2.2/32".parse::<IpNetwork>().unwrap(),
            gaps.next().unwrap()
        );
        assert_eq!(
            "192.168.2.3/32".parse::<IpNetwork>().unwrap(),
            gaps.next().unwrap()
        );

        let mut gaps = table.gap_ips_in_prefix(net);
        assert_eq!(
            "192.168.2.0".parse::<IpAddr>().unwrap(),
            gaps.next().unwrap()
        );
        assert_eq!(
            "192.168.2.1".parse::<IpAddr>().unwrap(),
            gaps.next().unwrap()
        );

        let net: Ipv6Network = "2001:db8::/64".parse().unwrap();

        let mut gaps = table.gap_ips_in_prefix(net.into());
        assert_eq!(
            "2001:db8::".parse::<IpAddr>().unwrap(),
            gaps.next().unwrap()
        );
    }

    #[test]
    fn test_iter_occupied() {
        let mut table = IpTable::new();

        let net1: IpNetwork = "192.168.0.0/24".parse().unwrap();
        let net2: IpNetwork = "192.168.1.0/24".parse().unwrap();

        table.insert(net1, 42);
        table.insert(net2, 43);

        let occupied = table.iter_occupied().collect::<Vec<_>>();
        assert_eq!(occupied, vec!["192.168.0.0/23".parse().unwrap(),]);

        let net3: IpNetwork = "192.168.3.0/24".parse().unwrap();
        table.insert(net3, 44);

        let occupied = table.iter_occupied().collect::<Vec<_>>();
        assert_eq!(
            occupied,
            vec![
                "192.168.3.0/24".parse().unwrap(),
                "192.168.0.0/23".parse().unwrap(),
            ]
        );

        let net4: IpNetwork = "192.168.2.0/24".parse().unwrap();
        table.insert(net4, 45);

        let occupied = table.iter_occupied().collect::<Vec<_>>();
        assert_eq!(occupied, vec!["192.168.0.0/22".parse().unwrap(),]);

        let net5: IpNetwork = "192.168.4.0/24".parse().unwrap();
        table.insert(net5, 46);
        let occupied = table.iter_occupied().collect::<Vec<_>>();
        assert_eq!(
            occupied,
            vec![
                "192.168.4.0/24".parse().unwrap(),
                "192.168.0.0/22".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn test_iter_occupied_prefix() {
        let mut table = IpTable::new();

        let net1: IpNetwork = "192.168.0.0/24".parse().unwrap();
        let net2: IpNetwork = "192.168.1.0/24".parse().unwrap();

        table.insert(net1, 42);
        table.insert(net2, 43);

        let net: IpNetwork = "192.168.0.0/16".parse().unwrap();

        let occupied = table.iter_occupied_prefix(net).collect::<Vec<_>>();

        assert_eq!(occupied, vec!["192.168.0.0/23".parse().unwrap(),]);
    }
}
