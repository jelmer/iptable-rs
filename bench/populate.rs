use criterion::{criterion_group, criterion_main, Criterion};
use ipnetwork::Ipv4Network;
use iptable::Ipv4Table;
use rand::{Rng, RngExt, SeedableRng};
use rand::rngs::StdRng;

fn random_ipnetwork<R: Rng>(rng: &mut R) -> Ipv4Network {
    let ip: std::net::Ipv4Addr = std::net::Ipv4Addr::new(
        rng.random_range(0..255),
        rng.random_range(0..255),
        rng.random_range(0..255),
        rng.random_range(0..255),
    );

    let prefix: u8 = rng.random_range(0..32);

    Ipv4Network::new(ip, prefix).unwrap()
}

fn random_ipv4<R: Rng>(rng: &mut R) -> Ipv4Network {
    let ip = std::net::Ipv4Addr::new(
        rng.random_range(0..255),
        rng.random_range(0..255),
        rng.random_range(0..255),
        rng.random_range(0..255),
    );
    Ipv4Network::new(ip, 32).unwrap()
}

fn build_table(nets: &[(Ipv4Network, u32)]) -> Ipv4Table<u32> {
    nets.iter().copied().collect()
}

fn populate_benchmark(c: &mut Criterion) {
    // Deterministic seed so we compare apples to apples across runs.
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let nets: Vec<(Ipv4Network, u32)> = (0..10_000)
        .map(|_| (random_ipnetwork(&mut rng), rng.random_range(0..1000)))
        .collect();

    // Original "build + 1k longest-prefix-match lookups" workload.
    c.bench_function("populate", |b| {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        b.iter(|| {
            let table = build_table(&nets);
            for _ in 0..1000 {
                let net = random_ipnetwork(&mut rng);
                for prefix in table.iter_containing_prefixes(net) {
                    let _ = prefix;
                }
            }
        });
    });

    // Pure build cost: insert 10k entries.
    c.bench_function("build_only", |b| {
        b.iter(|| {
            let _table = build_table(&nets);
        });
    });

    // Longest-prefix-match heavy: build once, then 100k LPM queries.
    let table = build_table(&nets);
    c.bench_function("lpm_100k", |b| {
        let mut rng = StdRng::seed_from_u64(0xABCDEF);
        b.iter(|| {
            for _ in 0..100_000 {
                let q = random_ipv4(&mut rng);
                let _ = table.get_containing_prefix(q);
            }
        });
    });

    // iter_containing_prefixes: same query workload, different API.
    c.bench_function("icp_100k", |b| {
        let mut rng = StdRng::seed_from_u64(0xABCDEF);
        b.iter(|| {
            for _ in 0..100_000 {
                let q = random_ipv4(&mut rng);
                for p in table.iter_containing_prefixes(q) {
                    let _ = p;
                }
            }
        });
    });
}

criterion_group!(benches, populate_benchmark);
criterion_main!(benches);
