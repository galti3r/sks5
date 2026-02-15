use criterion::{criterion_group, criterion_main, Criterion};

fn bench_hash_password(c: &mut Criterion) {
    // Note: password hashing is intentionally slow (Argon2id), so we use few iterations
    let mut group = c.benchmark_group("password");
    group.sample_size(10);
    group.bench_function("hash_password", |b| {
        b.iter(|| {
            let _ = sks5::auth::password::hash_password("test-password-123");
        });
    });
    group.finish();
}

fn bench_verify_password(c: &mut Criterion) {
    let hash = sks5::auth::password::hash_password("test-password-123").unwrap();
    let mut group = c.benchmark_group("password_verify");
    group.sample_size(10);
    group.bench_function("verify_password_correct", |b| {
        let hash = hash.clone();
        b.iter(|| {
            let _ = sks5::auth::password::verify_password("test-password-123", &hash);
        });
    });
    group.bench_function("verify_password_wrong", |b| {
        let hash = hash.clone();
        b.iter(|| {
            let _ = sks5::auth::password::verify_password("wrong-password", &hash);
        });
    });
    group.finish();
}

fn bench_generate_password(c: &mut Criterion) {
    let mut group = c.benchmark_group("password_generate");
    group.bench_function("generate_16", |b| {
        b.iter(|| {
            let _ = sks5::auth::password::generate_password(16);
        });
    });
    group.bench_function("generate_64", |b| {
        b.iter(|| {
            let _ = sks5::auth::password::generate_password(64);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_hash_password,
    bench_verify_password,
    bench_generate_password
);
criterion_main!(benches);
