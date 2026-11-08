use komizo::deployment::{
    capacity::{Allocation, Capacity, Infrastructure, verify_cgroup},
    *,
};
use std::collections::BTreeMap;
fn limits(memory: u64) -> Limits {
    Limits {
        memory_bytes: memory << 20,
        memory_swap_bytes: (memory + 256) << 20,
        milli_cpus: 600,
        pids: 256,
    }
}
fn capacity() -> Capacity {
    Capacity {
        kind: "komizo.capacity".into(),
        version: 1,
        physical_memory_bytes: 1024 << 20,
        os_reserve_bytes: 192 << 20,
        physical_milli_cpus: 1000,
        os_reserve_milli_cpus: 100,
        limits: Limits {
            memory_bytes: 832 << 20,
            memory_swap_bytes: 1856 << 20,
            milli_cpus: 900,
            pids: 2048,
        },
        production: Limits {
            memory_bytes: 552 << 20,
            memory_swap_bytes: 1320 << 20,
            milli_cpus: 600,
            pids: 512,
        },
        previews: Limits {
            memory_bytes: 96 << 20,
            memory_swap_bytes: 352 << 20,
            milli_cpus: 100,
            pids: 128,
        },
        control: Infrastructure {
            limits: Limits {
                memory_bytes: 192 << 20,
                memory_swap_bytes: 256 << 20,
                milli_cpus: 600,
                pids: 256,
            },
            controls: ResourceControls {
                memory_low_bytes: 40 << 20,
                ..Default::default()
            },
        },
        proxy: Infrastructure {
            limits: Limits {
                memory_bytes: 96 << 20,
                memory_swap_bytes: 160 << 20,
                milli_cpus: 100,
                pids: 128,
            },
            controls: ResourceControls {
                memory_low_bytes: 32 << 20,
                ..Default::default()
            },
        },
        infrastructure_reserve_bytes: 96 << 20,
        startup_memory_bytes: 64 << 20,
        disk_reserve_bytes: 512 << 20,
        max_instances: 16,
    }
}
fn allocation(app: &str, memory: u64, reserve: u64) -> Allocation {
    Allocation {
        application: app.into(),
        instance: "production".into(),
        release_digest: format!("sha256:{}", "a".repeat(64)),
        limits: limits(memory),
        memory_reservation_bytes: reserve << 20,
        startup_memory_bytes: 0,
        is_static: false,
    }
}

#[test]
fn shared_parent_bounds_bursts_while_admission_counts_real_reservations() {
    let first = allocation("mailroom", 384, 256);
    let second = allocation("reports", 192, 80);
    let records = BTreeMap::from([("mailroom--production".into(), first)]);
    capacity().admit(&records, &second).unwrap(); // Burst ceilings exceed the parent; reservations fit.
    let mut excessive = second.clone();
    excessive.memory_reservation_bytes = 300 << 20;
    excessive.limits = limits(384);
    assert!(capacity().admit(&records, &excessive).is_err());
    let mut startup_records = records.clone();
    startup_records
        .get_mut("mailroom--production")
        .unwrap()
        .startup_memory_bytes = 64 << 20;
    let mut startup = second;
    startup.startup_memory_bytes = 64 << 20;
    assert!(capacity().admit(&startup_records, &startup).is_err());
    let mut outside = allocation("reports", 600, 80);
    assert!(capacity().admit(&records, &outside).is_err());
    outside.instance = "pr-1".into();
    outside.limits = limits(96);
    assert!(capacity().admit(&records, &outside).is_err());
}

#[test]
fn kernel_evidence_must_enforce_memory_cpu_pids_reservation_and_io() {
    let dir = tempfile::tempdir().unwrap();
    let l = limits(192);
    let controls = ResourceControls {
        memory_low_bytes: 80 << 20,
        memory_high_bytes: 160 << 20,
        cpu_weight: Some(1000),
        io_weight: None,
        io_max: vec![IoRate {
            device: "253:0".into(),
            read_bytes_per_second: 16777216,
            write_bytes_per_second: 4194304,
        }],
    };
    for (name, value) in [
        ("memory.max", l.memory_bytes.to_string()),
        (
            "memory.swap.max",
            (l.memory_swap_bytes - l.memory_bytes).to_string(),
        ),
        ("pids.max", l.pids.to_string()),
        ("memory.low", controls.memory_low_bytes.to_string()),
        ("memory.high", controls.memory_high_bytes.to_string()),
        ("cpu.weight", "1000".into()),
        ("cpu.max", "600000 1000000".into()),
        (
            "io.max",
            "253:0 rbps=16777216 wbps=4194304 riops=max wiops=max".into(),
        ),
    ] {
        std::fs::write(dir.path().join(name), value).unwrap();
    }
    verify_cgroup(dir.path(), &l, &controls).unwrap();
    for (name, unsafe_value) in [
        ("memory.max", "max"),
        ("cpu.max", "max 1000000"),
        ("pids.max", "max"),
        ("memory.low", "0"),
        ("io.max", "253:0 rbps=max wbps=max"),
    ] {
        let path = dir.path().join(name);
        let original = std::fs::read(&path).unwrap();
        std::fs::write(&path, unsafe_value).unwrap();
        assert!(
            verify_cgroup(dir.path(), &l, &controls).is_err(),
            "accepted ineffective {name}"
        );
        std::fs::write(&path, original).unwrap();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn submission_identity_is_obtained_from_the_actual_kernel_peer() {
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(
        komizo::deployment::transport::peer_uid(&receiver).unwrap(),
        unsafe { libc::geteuid() }
    );
    drop(sender);
}
