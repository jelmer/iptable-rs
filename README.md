# IPTable

This create contains an efficient data structure for storing and querying values by CIDR.

# Examples

```rust
use iptable::Ipv4Table;
use ipnetwork::Ipv4Network;

let mut table = Ipv4Table::new();
table.insert("192.168.2.0/24".parse::<Ipv4Network>().unwrap(), 42);
table.insert("192.168.1.0/24".parse::<Ipv4Network>().unwrap(), 43);

assert_eq!(table.get("192.168.2.0/24".parse::<Ipv4Network>().unwrap()), Some(&42));

// Iterate over the prefixes under a given prefix
let ipnet: Ipv4Network = "192.168.0.0/16".parse().unwrap();
let relevant = table.iter_prefix(ipnet).collect::<Vec<_>>();
assert_eq!(2, relevant.len());

// Merge entries with longer prefixes
let merged_table = table.merge_longer_prefixes(16, |a, b| a + b);
assert_eq!(
    merged_table.iter().collect::<Vec<_>>(),
    vec![(&"192.168.0.0/16".parse().unwrap(), &85)]
);
```
