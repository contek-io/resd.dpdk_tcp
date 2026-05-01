// Prints every counter name from ALL_COUNTER_NAMES, one per line.
// Consumed by scripts/counter-coverage-static.sh.
fn main() {
    for n in dpdk_net_core::counters::ALL_COUNTER_NAMES {
        println!("{n}");
    }
}
