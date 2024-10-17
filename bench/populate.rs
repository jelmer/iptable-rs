use criterion::{criterion_group, criterion_main, Criterion};
use ipnetwork::Ipv4Network;
use iptable::Ipv4Table;
use rand::Rng;

fn random_ipnetwork() -> Ipv4Network {
    let mut rng = rand::thread_rng();

    let ip: std::net::Ipv4Addr = std::net::Ipv4Addr::new(
        rng.gen_range(0..255),
        rng.gen_range(0..255),
        rng.gen_range(0..255),
        rng.gen_range(0..255),
    );

    let prefix: u8 = rng.gen_range(0..32);

    Ipv4Network::new(ip, prefix).unwrap()
}

fn populate_benchmark(c: &mut Criterion) {
    let mut nets = vec![];
    let mut rng = rand::thread_rng();

    c.bench_function("populate", |b| {
        for _ in 0..10_000 {
            let net = random_ipnetwork();
            nets.push((net, rng.gen_range(0..1000)));
        }
        b.iter(|| {
            let table: Ipv4Table<u32> = nets.clone().into_iter().collect::<Ipv4Table<u32>>();

            for _i in 0..1000 {
                let net = random_ipnetwork();
                for prefix in table.iter_containing_prefixes(net) {
                    let _ = prefix;
                }
            }
        });
    });
}

criterion_group!(benches, populate_benchmark);
criterion_main!(benches);
