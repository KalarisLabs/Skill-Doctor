use criterion::{black_box, criterion_group, criterion_main, Criterion};
use skill_doctor_core::finding::Severity;
use skill_doctor_core::l0;
use skill_doctor_core::l5::{self, ReportOptions};
use std::path::PathBuf;

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
}

fn bench_l0_intake(c: &mut Criterion) {
    let benign = fixtures_path().join("benign").join("hello-skill");
    c.bench_function("l0_intake_benign", |b| {
        b.iter(|| {
            let bundle = l0::intake(black_box(&benign)).unwrap();
            black_box(bundle);
        });
    });
}

fn bench_full_analysis(c: &mut Criterion) {
    let benign = fixtures_path().join("benign").join("hello-skill");
    let bundle = l0::intake(&benign).unwrap();
    let opts = ReportOptions {
        fail_on: Severity::High,
        deterministic: true,
    };

    c.bench_function("l5_full_analysis_benign", |b| {
        b.iter(|| {
            let report = l5::analyze(black_box(&bundle), black_box(&opts));
            black_box(report);
        });
    });
}

criterion_group!(benches, bench_l0_intake, bench_full_analysis);
criterion_main!(benches);
