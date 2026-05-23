#![deny(missing_docs)]
//! # IPTable
//!
//! This crate contains an efficient data structure for storing and querying values by CIDR.
//!
//! Internally entries are stored in a path-compressed binary radix (Patricia) trie keyed by
//! the bits of the network address. Lookup, longest-prefix-match and gap operations all run
//! in time proportional to the prefix length rather than the number of entries.
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

    /// Get the bit at the given position (0 = most significant) of the network address.
    fn bit_at(self, index: u8) -> bool;

    /// Length of the longest common bit prefix (from the MSB) of two networks'
    /// address fields. Returns at most `addr_size()`.
    ///
    /// Used by the trie to find divergence points in a single XOR + count-leading-zeros
    /// rather than bit-by-bit comparison.
    fn common_prefix_len(self, other: Self) -> u8;

    /// Family index: 0 for IPv4-shaped, 1 for IPv6-shaped.
    ///
    /// Used to keep disjoint address families in separate subtries when the same
    /// table can hold both (i.e. when `N = IpNetwork`).
    fn family(self) -> u8;
}

impl Subnet for Ipv4Network {
    type Address = Ipv4Addr;

    fn prefix(self) -> u8 {
        Ipv4Network::prefix(self)
    }
    fn last(self) -> Self {
        let p = self.prefix();
        let host_mask: u32 = if p == 0 { !0u32 } else { (!0u32) >> p };
        let last = self.ip().to_bits() | host_mask;
        Ipv4Network::new(Ipv4Addr::from_bits(last), p).unwrap()
    }

    fn is_subnet_of(self, other: Self) -> bool {
        Ipv4Network::is_subnet_of(self, other)
    }

    fn with_prefix_len(self, prefix: u8) -> Self {
        assert!(prefix <= 32);
        let mask: u32 = if prefix == 0 {
            0
        } else {
            (!0u32) << (32 - prefix)
        };
        let ip = self.ip().to_bits() & mask;
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

    fn bit_at(self, index: u8) -> bool {
        (self.ip().to_bits() >> (31 - index)) & 1 != 0
    }

    fn common_prefix_len(self, other: Self) -> u8 {
        let xor = self.ip().to_bits() ^ other.ip().to_bits();
        if xor == 0 {
            32
        } else {
            xor.leading_zeros() as u8
        }
    }

    fn family(self) -> u8 {
        0
    }
}

impl Subnet for Ipv6Network {
    type Address = Ipv6Addr;

    fn prefix(self) -> u8 {
        Ipv6Network::prefix(&self)
    }
    fn last(self) -> Self {
        let p = self.prefix();
        let host_mask: u128 = if p == 0 { !0u128 } else { (!0u128) >> p };
        let last = self.ip().to_bits() | host_mask;
        Ipv6Network::new(Ipv6Addr::from_bits(last), p).unwrap()
    }

    fn is_subnet_of(self, other: Self) -> bool {
        Ipv6Network::is_subnet_of(self, other)
    }

    fn with_prefix_len(self, prefix: u8) -> Self {
        assert!(prefix <= 128);
        let mask: u128 = if prefix == 0 {
            0
        } else {
            (!0u128) << (128 - prefix)
        };
        let ip = self.ip().to_bits() & mask;
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

    fn bit_at(self, index: u8) -> bool {
        (self.ip().to_bits() >> (127 - index)) & 1 != 0
    }

    fn common_prefix_len(self, other: Self) -> u8 {
        let xor = self.ip().to_bits() ^ other.ip().to_bits();
        if xor == 0 {
            128
        } else {
            xor.leading_zeros() as u8
        }
    }

    fn family(self) -> u8 {
        1
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

    fn bit_at(self, index: u8) -> bool {
        match self {
            IpNetwork::V4(net) => net.bit_at(index),
            IpNetwork::V6(net) => net.bit_at(index),
        }
    }

    fn common_prefix_len(self, other: Self) -> u8 {
        match (self, other) {
            (IpNetwork::V4(a), IpNetwork::V4(b)) => a.common_prefix_len(b),
            (IpNetwork::V6(a), IpNetwork::V6(b)) => a.common_prefix_len(b),
            // Different families never share a prefix in this trie — but the
            // trie keeps families in separate subtries so this case shouldn't
            // be reached from internal call sites.
            _ => 0,
        }
    }

    fn family(self) -> u8 {
        match self {
            IpNetwork::V4(_) => 0,
            IpNetwork::V6(_) => 1,
        }
    }
}

/// Index into the arena of trie nodes. `u32::MAX` is used as the `None` sentinel.
type NodeId = u32;
const NONE_ID: NodeId = u32::MAX;

/// A node in the Patricia trie.
///
/// `key` always has its network bits truncated to `key.prefix()` (= the node's depth).
/// If `value` is `Some`, this node represents a stored entry; otherwise it is an
/// internal branch node that must have both children set to a valid `NodeId`.
struct Node<N: Subnet, T> {
    key: N,
    value: Option<T>,
    children: [NodeId; 2],
}

impl<N: Subnet, T> Node<N, T> {
    fn new_leaf(key: N, value: T) -> Self {
        Self {
            key,
            value: Some(value),
            children: [NONE_ID, NONE_ID],
        }
    }
}

/// Return the index of the first bit at which `a` and `b` differ within `[0, to)`,
/// or `None` if they agree on all those bits.
#[inline]
fn first_diff_bit_prefix<N: Subnet>(a: N, b: N, to: u8) -> Option<u8> {
    let cpl = a.common_prefix_len(b);
    if cpl >= to {
        None
    } else {
        Some(cpl)
    }
}

/// Base structure for storing values by CIDR.
///
/// Nodes are arena-allocated in a single `Vec`: `Node::children` and `roots` use
/// `NodeId` (= `u32`) indices into `nodes`. Removed slots are reused via `free`,
/// so a long-lived table with churn doesn't grow unboundedly.
pub struct GenericIpTable<N: Subnet, T> {
    nodes: Vec<Node<N, T>>,
    free: Vec<NodeId>,
    /// Separate subtries per address family — used so a single `IpTable`
    /// can hold both IPv4 and IPv6 entries while keeping each family's trie clean.
    roots: [NodeId; 2],
    len: usize,
}

/// A table for storing values by IPv4 or IPv6 CIDR.
pub type IpTable<T> = GenericIpTable<IpNetwork, T>;

/// Alias for IpTable
pub type UniversalIpTable<T> = IpTable<T>;

/// A table for storing values by IPv4 CIDR.
pub type Ipv4Table<T> = GenericIpTable<Ipv4Network, T>;

/// A table for storing values by IPv6 CIDR.
pub type Ipv6Table<T> = GenericIpTable<Ipv6Network, T>;

impl<N: Subnet, T> Default for GenericIpTable<N, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N: Subnet, T> GenericIpTable<N, T> {
    /// Create a new table.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            free: Vec::new(),
            roots: [NONE_ID, NONE_ID],
            len: 0,
        }
    }

    /// Returns the number of elements in the table.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Allocate a node in the arena, reusing a freelist slot if available.
    #[inline]
    fn alloc(&mut self, node: Node<N, T>) -> NodeId {
        if let Some(id) = self.free.pop() {
            self.nodes[id as usize] = node;
            id
        } else {
            let id = self.nodes.len() as u32;
            self.nodes.push(node);
            id
        }
    }

    /// Mark a node slot as free, taking out its value (which is dropped) so the
    /// slot holds a vacant placeholder until the next `alloc` overwrites it.
    #[inline]
    fn free_node(&mut self, id: NodeId) {
        let n = &mut self.nodes[id as usize];
        n.value = None;
        n.children = [NONE_ID, NONE_ID];
        self.free.push(id);
    }

    /// Set the child pointer at `(parent_id, bit)` to `child_id`, or if
    /// `parent_id == NONE_ID`, set the root of `fam` instead.
    #[inline]
    fn set_link(&mut self, parent_id: NodeId, bit: usize, fam: usize, child_id: NodeId) {
        if parent_id == NONE_ID {
            self.roots[fam] = child_id;
        } else {
            self.nodes[parent_id as usize].children[bit] = child_id;
        }
    }

    /// Insert a value into the table.
    pub fn insert<S: Into<N>>(&mut self, net: S, value: T) {
        let net: N = net.into();
        let key = net.with_prefix_len(net.prefix());
        let new_prefix = key.prefix();
        let fam = key.family() as usize;

        let mut parent_id: NodeId = NONE_ID;
        let mut parent_bit: usize = 0;
        let mut cur_id = self.roots[fam];

        loop {
            if cur_id == NONE_ID {
                let leaf = self.alloc(Node::new_leaf(key, value));
                self.set_link(parent_id, parent_bit, fam, leaf);
                self.len += 1;
                return;
            }
            let node_key = self.nodes[cur_id as usize].key;
            let node_prefix = node_key.prefix();
            let cmp_to = node_prefix.min(new_prefix);
            if let Some(diff) = first_diff_bit_prefix(node_key, key, cmp_to) {
                // Split: branch at depth `diff`.
                let branch_key = node_key.with_prefix_len(diff);
                let leaf_id = self.alloc(Node::new_leaf(key, value));
                let old_bit = node_key.bit_at(diff) as usize;
                let new_bit = key.bit_at(diff) as usize;
                debug_assert_ne!(old_bit, new_bit);
                let mut branch = Node {
                    key: branch_key,
                    value: None,
                    children: [NONE_ID, NONE_ID],
                };
                branch.children[old_bit] = cur_id;
                branch.children[new_bit] = leaf_id;
                let branch_id = self.alloc(branch);
                self.set_link(parent_id, parent_bit, fam, branch_id);
                self.len += 1;
                return;
            }
            if new_prefix == node_prefix {
                let slot = &mut self.nodes[cur_id as usize].value;
                if slot.is_none() {
                    self.len += 1;
                }
                *slot = Some(value);
                return;
            }
            if new_prefix < node_prefix {
                // New key is an ancestor of `cur`; insert a new node above it.
                let bit = node_key.bit_at(new_prefix) as usize;
                let mut new_node = Node::new_leaf(key, value);
                new_node.children[bit] = cur_id;
                let new_id = self.alloc(new_node);
                self.set_link(parent_id, parent_bit, fam, new_id);
                self.len += 1;
                return;
            }
            // new_prefix > node_prefix: descend.
            let bit = key.bit_at(node_prefix) as usize;
            parent_id = cur_id;
            parent_bit = bit;
            cur_id = self.nodes[cur_id as usize].children[bit];
        }
    }

    /// Walk down to the node that exactly matches `key`, returning its id, or
    /// `NONE_ID` if no such entry exists.
    #[inline]
    fn find_id(&self, key: N) -> NodeId {
        let target_prefix = key.prefix();
        let fam = key.family() as usize;
        let mut cur = self.roots[fam];
        while cur != NONE_ID {
            let node = &self.nodes[cur as usize];
            let np = node.key.prefix();
            if np > target_prefix {
                return NONE_ID;
            }
            if first_diff_bit_prefix(node.key, key, np).is_some() {
                return NONE_ID;
            }
            if np == target_prefix {
                return if node.value.is_some() { cur } else { NONE_ID };
            }
            let bit = key.bit_at(np) as usize;
            cur = node.children[bit];
        }
        NONE_ID
    }

    /// Get a value from the table.
    ///
    /// Exact match only.
    pub fn get<S: Into<N>>(&self, net: S) -> Option<&T> {
        let key = net.into();
        let key = key.with_prefix_len(key.prefix());
        let id = self.find_id(key);
        if id == NONE_ID {
            None
        } else {
            self.nodes[id as usize].value.as_ref()
        }
    }

    /// Get a mutable reference to a value in the table.
    ///
    /// Exact match only.
    pub fn get_mut<S: Into<N>>(&mut self, net: S) -> Option<&mut T> {
        let key = net.into();
        let key = key.with_prefix_len(key.prefix());
        let id = self.find_id(key);
        if id == NONE_ID {
            None
        } else {
            self.nodes[id as usize].value.as_mut()
        }
    }

    /// Remove a value from the table.
    pub fn remove<S: Into<N>>(&mut self, net: S) -> Option<T> {
        let key = net.into();
        let key = key.with_prefix_len(key.prefix());
        let target_prefix = key.prefix();
        let fam = key.family() as usize;

        // Walk down, remembering the parent chain so we can collapse upwards
        // after removing the leaf entry.
        let mut parent_id: NodeId = NONE_ID;
        let mut parent_bit: usize = 0;
        let mut cur = self.roots[fam];
        loop {
            if cur == NONE_ID {
                return None;
            }
            let node = &self.nodes[cur as usize];
            let np = node.key.prefix();
            if np > target_prefix {
                return None;
            }
            if first_diff_bit_prefix(node.key, key, np).is_some() {
                return None;
            }
            if np == target_prefix {
                break;
            }
            let bit = key.bit_at(np) as usize;
            parent_id = cur;
            parent_bit = bit;
            cur = node.children[bit];
        }
        let removed = self.nodes[cur as usize].value.take()?;
        self.len -= 1;

        // Collapse `cur` if it has 0 or 1 children.
        let (c0, c1) = {
            let n = &self.nodes[cur as usize];
            (n.children[0], n.children[1])
        };
        if c0 == NONE_ID && c1 == NONE_ID {
            // Leaf gone.
            self.set_link(parent_id, parent_bit, fam, NONE_ID);
            self.free_node(cur);
            // Now the parent might be a branch with no value and only one child.
            self.collapse_chain(fam);
        } else if c0 == NONE_ID || c1 == NONE_ID {
            // One child: replace cur with its only child.
            let only = if c0 == NONE_ID { c1 } else { c0 };
            self.set_link(parent_id, parent_bit, fam, only);
            self.free_node(cur);
        }
        // else: cur still has both children — leave it as a value-less branch.

        Some(removed)
    }

    /// After a leaf deletion, walk back along the parent chain (re-found by
    /// descending the tree again — the path is short) and collapse any branch
    /// nodes that now have no value and only one child.
    ///
    /// Because we already know which family to search and the path from root
    /// is unique, the cheapest way to do this is to re-walk from the root and
    /// remember parents on a small stack. The path is bounded by `addr_size()`,
    /// so this is constant work.
    fn collapse_chain(&mut self, fam: usize) {
        // We rebuild the path of (parent_id, child_bit, node_id) from root down
        // to the deepest node, then walk back up collapsing.
        let mut path: Vec<(NodeId, usize, NodeId)> = Vec::with_capacity(32);
        let mut parent_id: NodeId = NONE_ID;
        let mut parent_bit: usize = 0;
        let mut cur = self.roots[fam];
        // Walk to a leaf along an arbitrary path — but we need to find branch
        // nodes that have only one child *now*. Easier: traverse the whole
        // subtree and collapse bottom-up. Since `remove` is the only caller
        // and the cost is per-removal, traversing the whole family subtree is
        // wasteful for large tables. Instead just walk down following the only
        // possible chain of single-child branch nodes from the root.
        while cur != NONE_ID {
            path.push((parent_id, parent_bit, cur));
            let (c0, c1) = {
                let n = &self.nodes[cur as usize];
                (n.children[0], n.children[1])
            };
            // Keep going while exactly one child exists.
            if c0 != NONE_ID && c1 == NONE_ID {
                parent_id = cur;
                parent_bit = 0;
                cur = c0;
            } else if c1 != NONE_ID && c0 == NONE_ID {
                parent_id = cur;
                parent_bit = 1;
                cur = c1;
            } else {
                break;
            }
        }
        // Walk back up collapsing value-less branches with one child.
        while let Some((p_id, p_bit, n_id)) = path.pop() {
            let node = &self.nodes[n_id as usize];
            if node.value.is_some() {
                break;
            }
            let c0 = node.children[0];
            let c1 = node.children[1];
            if c0 != NONE_ID && c1 != NONE_ID {
                break;
            }
            if c0 == NONE_ID && c1 == NONE_ID {
                // Shouldn't happen for an internal value-less node (invariant),
                // but handle defensively.
                self.set_link(p_id, p_bit, fam, NONE_ID);
                self.free_node(n_id);
                continue;
            }
            let only = if c0 == NONE_ID { c1 } else { c0 };
            self.set_link(p_id, p_bit, fam, only);
            self.free_node(n_id);
        }
    }

    /// Get the entry for the given network.
    pub fn entry(&mut self, net: N) -> Entry<'_, N, T> {
        let key = net.with_prefix_len(net.prefix());
        if self.get(key).is_some() {
            Entry::Occupied(OccupiedEntry { table: self, key })
        } else {
            Entry::Vacant(VacantEntry { table: self, key })
        }
    }

    /// Iterate over the entries in the table, ordered by prefix.
    pub fn iter(&self) -> Iter<'_, N, T> {
        Iter::new(self, [self.roots[0], self.roots[1]])
    }

    /// Iterate over the prefixes under the given prefix, including the prefix itself.
    pub fn iter_prefix<S: Into<N>>(&self, prefix: S) -> Iter<'_, N, T> {
        let prefix: N = prefix.into();
        let prefix = prefix.with_prefix_len(prefix.prefix());
        let fam = prefix.family() as usize;
        let target_prefix = prefix.prefix();
        let mut cur = self.roots[fam];
        while cur != NONE_ID {
            let node = &self.nodes[cur as usize];
            let np = node.key.prefix();
            if np >= target_prefix {
                if first_diff_bit_prefix(node.key, prefix, target_prefix).is_none() {
                    return Iter::from_subtree(self, cur);
                }
                return Iter::empty(self);
            }
            if first_diff_bit_prefix(node.key, prefix, np).is_some() {
                return Iter::empty(self);
            }
            let bit = prefix.bit_at(np) as usize;
            cur = node.children[bit];
        }
        Iter::empty(self)
    }

    /// Iterate over the prefixes under the given prefix, excluding the prefix itself.
    pub fn iter_subprefixes<S: Into<N>>(&self, prefix: S) -> IterSubprefixes<'_, N, T> {
        let prefix: N = prefix.into();
        IterSubprefixes {
            inner: self.iter_prefix(prefix),
            skip: prefix.with_prefix_len(prefix.prefix()),
        }
    }

    /// Merge entries with longer prefixes into the target prefix.
    pub fn merge_longer_prefixes(self, target_prefix: u8, merge_fn: impl Fn(T, T) -> T) -> Self {
        let mut new_table = Self::new();

        for (net, value) in self.into_iter() {
            if net.prefix() >= target_prefix {
                let net = net.with_prefix_len(target_prefix);
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
        let key: N = net.into();
        let key = key.with_prefix_len(key.prefix());
        let target_prefix = key.prefix();
        let fam = key.family() as usize;
        let mut cur = self.roots[fam];
        let mut best: Option<(N, &T)> = None;
        while cur != NONE_ID {
            let node = &self.nodes[cur as usize];
            let np = node.key.prefix();
            if np > target_prefix {
                break;
            }
            if first_diff_bit_prefix(node.key, key, np).is_some() {
                break;
            }
            if let Some(v) = node.value.as_ref() {
                if np < target_prefix {
                    best = Some((node.key, v));
                }
            }
            if np == target_prefix {
                break;
            }
            let bit = key.bit_at(np) as usize;
            cur = node.children[bit];
        }
        best
    }

    /// Iterate over the shorter prefixes of the given network, longest first.
    pub fn iter_containing_prefixes<S: Into<N>>(&self, net: S) -> ContainingPrefixes<'_, N, T> {
        let key: N = net.into();
        let key = key.with_prefix_len(key.prefix());
        let target_prefix = key.prefix();
        let fam = key.family() as usize;
        let mut found: Vec<(N, &T)> = Vec::new();
        let mut cur = self.roots[fam];
        while cur != NONE_ID {
            let node = &self.nodes[cur as usize];
            let np = node.key.prefix();
            if np > target_prefix {
                break;
            }
            if first_diff_bit_prefix(node.key, key, np).is_some() {
                break;
            }
            if np < target_prefix {
                if let Some(v) = node.value.as_ref() {
                    found.push((node.key, v));
                }
            } else {
                break;
            }
            let bit = key.bit_at(np) as usize;
            cur = node.children[bit];
        }
        found.reverse();
        ContainingPrefixes {
            iter: found.into_iter(),
        }
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
        std::iter::from_fn(move || {
            while let Some(prefix) = todo.pop_first() {
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
        self.get(net).is_some()
    }

    /// Return values for all the prefixes in the table.
    pub fn values(&self) -> Values<'_, N, T> {
        Values { iter: self.iter() }
    }

    /// Retain only the entries that satisfy the predicate.
    pub fn retain<F: FnMut(&N, &T) -> bool>(&mut self, mut f: F) {
        let to_remove: Vec<N> = self
            .iter()
            .filter_map(|(k, v)| if !f(k, v) { Some(*k) } else { None })
            .collect();
        for k in to_remove {
            self.remove(k);
        }
    }

    /// Iterate over all gaps with a specific prefix length.
    pub fn gaps_with_prefix_len(&self, prefix: N, prefix_len: u8) -> impl Iterator<Item = N> + '_ {
        let mut todo = std::iter::once(prefix).collect::<std::collections::BTreeSet<_>>();
        std::iter::from_fn(move || {
            while let Some(prefix) = todo.pop_first() {
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
                let toggled = prefix.toggle_bit(prefix.prefix() - 1);
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
        self._iter_occupied(self.iter().map(|(k, _)| *k))
    }

    /// Iterate over the occupied prefixes in the table under a given prefix.
    ///
    /// This will yield the prefixes in order of length, longest first.
    pub fn iter_occupied_prefix(&self, prefix: N) -> impl Iterator<Item = N> + '_ {
        self._iter_occupied(self.iter_prefix(prefix).map(|(net, _)| *net))
    }
}

/// Iterator over the entries in a `GenericIpTable`, in `(network, prefix)` order.
///
/// The stack holds node ids still to visit in pre-order: when an id is popped the
/// corresponding node's value (if any) is yielded immediately, then its children
/// are pushed in reverse order (right before left) so the left subtree is
/// visited first.
pub struct Iter<'a, N: Subnet, T> {
    table: &'a GenericIpTable<N, T>,
    stack: Vec<NodeId>,
}

impl<'a, N: Subnet, T> Iter<'a, N, T> {
    fn new(table: &'a GenericIpTable<N, T>, roots: [NodeId; 2]) -> Self {
        let mut stack = Vec::new();
        // Push in reverse so family 0 pops first.
        if roots[1] != NONE_ID {
            stack.push(roots[1]);
        }
        if roots[0] != NONE_ID {
            stack.push(roots[0]);
        }
        Self { table, stack }
    }

    fn empty(table: &'a GenericIpTable<N, T>) -> Self {
        Self {
            table,
            stack: Vec::new(),
        }
    }

    fn from_subtree(table: &'a GenericIpTable<N, T>, root: NodeId) -> Self {
        let mut it = Self::empty(table);
        if root != NONE_ID {
            it.stack.push(root);
        }
        it
    }
}

impl<'a, N: Subnet, T> Iterator for Iter<'a, N, T> {
    type Item = (&'a N, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let id = self.stack.pop()?;
            let node = &self.table.nodes[id as usize];
            if node.children[1] != NONE_ID {
                self.stack.push(node.children[1]);
            }
            if node.children[0] != NONE_ID {
                self.stack.push(node.children[0]);
            }
            if let Some(v) = node.value.as_ref() {
                return Some((&node.key, v));
            }
        }
    }
}

/// Iterator over the proper sub-prefixes of a given prefix.
pub struct IterSubprefixes<'a, N: Subnet, T> {
    inner: Iter<'a, N, T>,
    skip: N,
}

impl<'a, N: Subnet, T> Iterator for IterSubprefixes<'a, N, T> {
    type Item = (&'a N, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (k, v) = self.inner.next()?;
            if *k != self.skip {
                return Some((k, v));
            }
        }
    }
}

/// Iterator over the values in a `GenericIpTable`.
pub struct Values<'a, N: Subnet, T> {
    iter: Iter<'a, N, T>,
}

impl<'a, N: Subnet, T> Iterator for Values<'a, N, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(_, v)| v)
    }
}

/// Iterator over the containing prefixes of a network, longest first.
pub struct ContainingPrefixes<'a, N: Subnet, T> {
    iter: std::vec::IntoIter<(N, &'a T)>,
}

impl<'a, N: Subnet, T> Iterator for ContainingPrefixes<'a, N, T> {
    type Item = (N, &'a T);
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

/// Owning iterator over `GenericIpTable`.
///
/// Mirrors `Iter` but takes ownership: pop a node id, yield its value (if any)
/// by `take`-ing it out of the arena, push children right-then-left so the
/// left subtree is visited first.
pub struct IntoIter<N: Subnet, T> {
    nodes: Vec<Node<N, T>>,
    stack: Vec<NodeId>,
}

impl<N: Subnet, T> Iterator for IntoIter<N, T> {
    type Item = (N, T);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let id = self.stack.pop()?;
            let node = &mut self.nodes[id as usize];
            let c1 = node.children[1];
            let c0 = node.children[0];
            let v = node.value.take();
            let key = node.key;
            if c1 != NONE_ID {
                self.stack.push(c1);
            }
            if c0 != NONE_ID {
                self.stack.push(c0);
            }
            if let Some(v) = v {
                return Some((key, v));
            }
        }
    }
}

impl<N: Subnet, T> IntoIterator for GenericIpTable<N, T> {
    type Item = (N, T);
    type IntoIter = IntoIter<N, T>;

    fn into_iter(self) -> Self::IntoIter {
        let mut stack = Vec::new();
        if self.roots[1] != NONE_ID {
            stack.push(self.roots[1]);
        }
        if self.roots[0] != NONE_ID {
            stack.push(self.roots[0]);
        }
        IntoIter {
            nodes: self.nodes,
            stack,
        }
    }
}

// Stub re-impl: actual semantics provided by the Iterator impl above is buggy
// (post-order). We provide an alternative via free function used by merge_longer_prefixes
// and the iter() based collection in tests.

/// Entry API for in-place modification.
pub enum Entry<'a, N: Subnet, T> {
    /// An occupied entry.
    Occupied(OccupiedEntry<'a, N, T>),
    /// A vacant entry.
    Vacant(VacantEntry<'a, N, T>),
}

/// An occupied entry in a `GenericIpTable`.
pub struct OccupiedEntry<'a, N: Subnet, T> {
    table: &'a mut GenericIpTable<N, T>,
    key: N,
}

/// A vacant entry in a `GenericIpTable`.
pub struct VacantEntry<'a, N: Subnet, T> {
    table: &'a mut GenericIpTable<N, T>,
    key: N,
}

impl<'a, N: Subnet, T> Entry<'a, N, T> {
    /// Ensure a value is in the entry by inserting the default if empty.
    pub fn or_insert(self, default: T) -> &'a mut T {
        match self {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(default),
        }
    }

    /// Ensure a value is in the entry by computing it from a closure if empty.
    pub fn or_insert_with<F: FnOnce() -> T>(self, default: F) -> &'a mut T {
        match self {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(default()),
        }
    }
}

impl<'a, N: Subnet, T> OccupiedEntry<'a, N, T> {
    /// Get a mutable reference to the value.
    pub fn into_mut(self) -> &'a mut T {
        self.table.get_mut(self.key).expect("occupied")
    }

    /// Get a reference to the value.
    pub fn get(&self) -> &T {
        self.table.get(self.key).expect("occupied")
    }

    /// Get a mutable reference to the value.
    pub fn get_mut(&mut self) -> &mut T {
        self.table.get_mut(self.key).expect("occupied")
    }

    /// Get the key of the entry.
    pub fn key(&self) -> &N {
        &self.key
    }
}

impl<'a, N: Subnet, T> VacantEntry<'a, N, T> {
    /// Insert a value into the vacant entry and return a mutable reference to it.
    pub fn insert(self, value: T) -> &'a mut T {
        self.table.insert(self.key, value);
        self.table.get_mut(self.key).expect("just inserted")
    }

    /// Get the key of the entry.
    pub fn key(&self) -> &N {
        &self.key
    }
}

impl<N: Subnet, T> FromIterator<(N, T)> for GenericIpTable<N, T> {
    fn from_iter<I: IntoIterator<Item = (N, T)>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let mut table = Self::new();
        let (lo, _) = iter.size_hint();
        if lo > 0 {
            table.nodes.reserve(lo);
        }
        for (k, v) in iter {
            table.insert(k, v);
        }
        table
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
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<N: Subnet, T: Clone> Clone for GenericIpTable<N, T> {
    fn clone(&self) -> Self {
        let mut new_table = Self::new();
        for (k, v) in self.iter() {
            new_table.insert(*k, v.clone());
        }
        new_table
    }
}

impl<N: Subnet, T: PartialEq> PartialEq for GenericIpTable<N, T> {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        self.iter().eq(other.iter())
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

    #[test]
    fn test_partial_eq() {
        let mut table1 = IpTable::new();
        let mut table2 = IpTable::new();

        let net1: IpNetwork = "192.168.0.0/24".parse().unwrap();
        table1.insert(net1, 42);
        table2.insert(net1, 42);

        assert_eq!(table1, table2);

        let net2: IpNetwork = "192.168.1.0/24".parse().unwrap();
        table2.insert(net2, 43);

        assert_ne!(table1, table2);
    }

    #[test]
    fn test_debug_fmt() {
        let mut table = IpTable::new();
        let net: IpNetwork = "192.168.0.0/24".parse().unwrap();
        table.insert(net, 42);

        let debug_str = format!("{:?}", table);
        let expected = "{V4(Ipv4Network { addr: 192.168.0.0, prefix: 24 }): 42}";
        assert_eq!(debug_str, expected);

        let empty_table = IpTable::<i32>::new();
        let empty_debug = format!("{:?}", empty_table);
        assert_eq!(empty_debug, "{}");
    }

    #[test]
    fn test_ipv6_is_subnet_of() {
        let net1: Ipv6Network = "2001:db8::/32".parse().unwrap();
        let net2: Ipv6Network = "2001:db8::/64".parse().unwrap();
        let net3: Ipv6Network = "2001:db9::/64".parse().unwrap();

        assert!(net2.is_subnet_of(net1));
        assert!(!net1.is_subnet_of(net2));
        assert!(!net3.is_subnet_of(net1));
    }

    #[test]
    fn test_iter_subprefixes() {
        let mut table = IpTable::new();
        let parent: IpNetwork = "192.168.0.0/16".parse().unwrap();
        let child1: IpNetwork = "192.168.1.0/24".parse().unwrap();
        let child2: IpNetwork = "192.168.2.0/24".parse().unwrap();

        table.insert(parent, 1);
        table.insert(child1, 2);
        table.insert(child2, 3);

        let subprefixes = table.iter_subprefixes(parent).collect::<Vec<_>>();
        assert_eq!(subprefixes, vec![(&child1, &2), (&child2, &3)]);

        let empty_table = IpTable::<i32>::new();
        let empty_subs = empty_table.iter_subprefixes(parent).collect::<Vec<_>>();
        assert_eq!(empty_subs, vec![]);
    }

    #[test]
    fn test_ipv6_last() {
        let net: Ipv6Network = "2001:db8::/64".parse().unwrap();
        let last = net.last();

        assert_eq!(last.prefix(), 64);
        assert_ne!(last.ip(), net.ip());

        let net_full: Ipv6Network = "2001:db8::ffff:ffff:ffff:ffff/64".parse().unwrap();
        let last_full = net_full.last();
        assert_eq!(last_full.ip(), last.ip());
    }

    #[test]
    fn test_ipv4_last() {
        let net: Ipv4Network = "192.168.1.0/24".parse().unwrap();
        let last = net.last();

        assert_eq!(last.prefix(), 24);
        assert_ne!(last.ip(), net.ip());

        let net_full: Ipv4Network = "192.168.1.255/24".parse().unwrap();
        let last_full = net_full.last();
        assert_eq!(last_full.ip(), last.ip());
    }

    #[test]
    fn test_ipv6_toggle_bit() {
        let net: Ipv6Network = "2001:db8::/64".parse().unwrap();
        let toggled = net.toggle_bit(63);

        assert_ne!(toggled, net);
        assert_eq!(toggled.prefix(), net.prefix());

        let toggled_back = toggled.toggle_bit(63);
        assert_eq!(toggled_back, net);
    }

    #[test]
    fn test_ipv6_addr_size() {
        let net: Ipv6Network = "2001:db8::/64".parse().unwrap();
        assert_eq!(net.addr_size(), 128);
    }

    #[test]
    fn test_ipv4_addr_size() {
        let net: Ipv4Network = "192.168.1.0/24".parse().unwrap();
        assert_eq!(net.addr_size(), 32);
    }

    #[test]
    fn test_values() {
        let mut table = IpTable::new();
        let net1: IpNetwork = "192.168.0.0/24".parse().unwrap();
        let net2: IpNetwork = "192.168.1.0/24".parse().unwrap();

        table.insert(net1, 42);
        table.insert(net2, 43);

        let values = table.values().collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert!(values.contains(&&42));
        assert!(values.contains(&&43));

        let empty_table = IpTable::<i32>::new();
        let empty_values = empty_table.values().collect::<Vec<_>>();
        assert_eq!(empty_values.len(), 0);
    }

    #[test]
    fn test_replace_value() {
        let mut table = IpTable::new();
        let net: IpNetwork = "192.168.0.0/24".parse().unwrap();
        table.insert(net, 1);
        assert_eq!(table.len(), 1);
        table.insert(net, 2);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(net), Some(&2));
    }

    #[test]
    fn test_mixed_v4_v6() {
        let mut table = IpTable::new();
        let v4: IpNetwork = "10.0.0.0/8".parse().unwrap();
        let v6: IpNetwork = "2001:db8::/32".parse().unwrap();
        table.insert(v4, 1);
        table.insert(v6, 2);
        assert_eq!(table.len(), 2);

        // Iteration order: V4 first, then V6 (matches BTreeMap on enum).
        let entries = table.iter().collect::<Vec<_>>();
        assert_eq!(entries, vec![(&v4, &1), (&v6, &2)]);

        // V4 lookup should not find V6 entries and vice versa.
        let v4_query: IpNetwork = "10.1.2.3/32".parse().unwrap();
        assert_eq!(table.get_containing_prefix(v4_query), Some((v4, &1)));

        // Removing one family doesn't affect the other.
        assert_eq!(table.remove(v4), Some(1));
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(v6), Some(&2));
    }

    #[test]
    fn test_root_prefix_zero() {
        let mut table = IpTable::new();
        let zero: IpNetwork = "0.0.0.0/0".parse().unwrap();
        table.insert(zero, 99);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(table.get_containing_prefix(ip), Some((zero, &99)));
        assert_eq!(table.get(zero), Some(&99));
    }

    #[test]
    fn test_insert_split_then_remove_collapse() {
        // Two leaves under a branch; removing one should collapse the branch away.
        let mut table = IpTable::new();
        let a: IpNetwork = "10.0.0.0/24".parse().unwrap();
        let b: IpNetwork = "10.0.1.0/24".parse().unwrap();
        table.insert(a, 1);
        table.insert(b, 2);
        assert_eq!(table.iter().count(), 2);
        assert_eq!(table.remove(a), Some(1));
        assert_eq!(table.iter().count(), 1);
        assert_eq!(table.get(b), Some(&2));
        assert_eq!(table.remove(b), Some(2));
        assert!(table.is_empty());
    }

    #[test]
    fn test_insert_ancestor_after_descendant() {
        // Insert a child first, then its parent — exercises the "new key is ancestor" branch.
        let mut table = IpTable::new();
        let child: IpNetwork = "192.168.1.0/24".parse().unwrap();
        let parent: IpNetwork = "192.168.0.0/16".parse().unwrap();
        table.insert(child, 1);
        table.insert(parent, 2);
        assert_eq!(table.len(), 2);
        assert_eq!(table.get(child), Some(&1));
        assert_eq!(table.get(parent), Some(&2));
        assert_eq!(table.get_containing_prefix(child), Some((parent, &2)));
    }

    #[test]
    fn test_iter_order_many() {
        // Use BTreeMap as the reference ordering oracle.
        use std::collections::BTreeMap;
        let mut table = IpTable::new();
        let mut reference = BTreeMap::new();
        let nets: Vec<IpNetwork> = [
            "10.0.0.0/8",
            "10.1.0.0/16",
            "10.1.2.0/24",
            "10.1.2.3/32",
            "10.255.255.255/32",
            "192.168.0.0/16",
            "192.168.0.0/24",
            "192.168.0.128/25",
            "0.0.0.0/0",
            "2001:db8::/32",
            "2001:db8:1::/48",
            "::/0",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        for (i, &n) in nets.iter().enumerate() {
            table.insert(n, i);
            reference.insert(n, i);
        }
        let got: Vec<_> = table.iter().map(|(k, v)| (*k, *v)).collect();
        let want: Vec<_> = reference.into_iter().collect();
        assert_eq!(got, want);
    }

    #[test]
    fn test_iter_containing_prefixes_order() {
        let mut table = IpTable::new();
        let a: IpNetwork = "10.0.0.0/8".parse().unwrap();
        let b: IpNetwork = "10.1.0.0/16".parse().unwrap();
        let c: IpNetwork = "10.1.2.0/24".parse().unwrap();
        table.insert(a, 1);
        table.insert(b, 2);
        table.insert(c, 3);

        // Query a /32 inside all three: should yield c, b, a (longest-first).
        let query: IpNetwork = "10.1.2.3/32".parse().unwrap();
        let got: Vec<_> = table
            .iter_containing_prefixes(query)
            .map(|(k, v)| (k, *v))
            .collect();
        assert_eq!(got, vec![(c, 3), (b, 2), (a, 1)]);
    }

    #[test]
    fn test_into_iter_order() {
        let mut table = IpTable::new();
        let nets: Vec<IpNetwork> = [
            "10.0.0.0/8",
            "10.1.0.0/16",
            "192.168.0.0/16",
            "2001:db8::/32",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        for (i, &n) in nets.iter().enumerate() {
            table.insert(n, i);
        }
        let got: Vec<_> = table.into_iter().collect();
        let want: Vec<_> = nets.into_iter().zip(0..).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn test_entry_api() {
        let mut table = IpTable::new();
        let net: IpNetwork = "10.0.0.0/8".parse().unwrap();
        *table.entry(net).or_insert(0) += 5;
        *table.entry(net).or_insert(0) += 3;
        assert_eq!(table.get(net), Some(&8));
    }

    #[test]
    fn test_retain() {
        let mut table = IpTable::new();
        let a: IpNetwork = "10.0.0.0/8".parse().unwrap();
        let b: IpNetwork = "192.168.0.0/16".parse().unwrap();
        let c: IpNetwork = "2001:db8::/32".parse().unwrap();
        table.insert(a, 1);
        table.insert(b, 2);
        table.insert(c, 3);
        table.retain(|_k, v| *v != 2);
        assert_eq!(table.len(), 2);
        assert!(table.contains(a));
        assert!(!table.contains(b));
        assert!(table.contains(c));
    }

    #[test]
    fn test_random_insert_remove_lookup_matches_btreemap() {
        use std::collections::BTreeMap;

        // Deterministic PRNG so failures are reproducible.
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut rand = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        let mut table: Ipv4Table<u32> = Ipv4Table::new();
        let mut reference: BTreeMap<Ipv4Network, u32> = BTreeMap::new();

        for _ in 0..2_000 {
            let bits = (rand() & 0xFFFFFFFF) as u32;
            let prefix = (rand() % 33) as u8;
            let ip = Ipv4Addr::from_bits(bits);
            let net = Ipv4Network::new(ip, prefix).unwrap();
            let net = net.with_prefix_len(prefix);
            let v = (rand() & 0xFFFF) as u32;
            let op = rand() % 4;
            match op {
                0 | 1 => {
                    table.insert(net, v);
                    reference.insert(net, v);
                }
                2 => {
                    let got = table.remove(net);
                    let want = reference.remove(&net);
                    assert_eq!(got, want, "remove mismatch for {:?}", net);
                }
                _ => {
                    let got = table.get(net).copied();
                    let want = reference.get(&net).copied();
                    assert_eq!(got, want, "get mismatch for {:?}", net);
                }
            }
        }

        assert_eq!(table.len(), reference.len());
        let got: Vec<_> = table.iter().map(|(k, v)| (*k, *v)).collect();
        let want: Vec<_> = reference.into_iter().collect();
        assert_eq!(got, want);
    }

    #[test]
    fn test_surrounding_gaps_edge_case() {
        let parent: IpNetwork = "192.168.2.0/24".parse().unwrap();
        let child: IpNetwork = "192.168.2.0/26".parse().unwrap();

        let gaps = surrounding_gaps(parent, child, None).collect::<Vec<_>>();
        assert_eq!(
            gaps,
            vec![
                "192.168.2.128/25".parse().unwrap(),
                "192.168.2.64/26".parse().unwrap(),
            ]
        );

        let parent: IpNetwork = "192.168.2.0/24".parse().unwrap();
        let child: IpNetwork = "192.168.2.128/25".parse().unwrap();

        let gaps = surrounding_gaps(parent, child, None).collect::<Vec<_>>();
        assert_eq!(gaps, vec!["192.168.2.0/25".parse().unwrap()]);
    }
}
