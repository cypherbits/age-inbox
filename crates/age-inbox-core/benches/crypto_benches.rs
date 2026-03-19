use age::x25519::{Identity, Recipient};
use age_inbox_core::inbox_core::{
    create_vault, decrypt_age_file_range_to_writer, decrypt_age_file_to_writer, decrypt_metadata_file, encrypt_metadata_file, encrypt_reader_to_age_file, lock_vault, unlock_vault, FileMetadata, UnlockedVault, VaultPermissions
};
use std::collections::HashMap;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use tokio::runtime::Runtime;

fn generate_keys() -> (Identity, Recipient) {
    let identity = Identity::generate();
    let recipient = identity.to_public();
    (identity, recipient)
}

fn bench_encrypt_reader_to_age_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_reader_to_age_file");
    let rt = Runtime::new().unwrap();

    // Probaremos con un archivo de 1MB y 10MB
    for size_kb in [1024, 10240].iter() {
        let size_bytes = (size_kb * 1024) as u64;
        group.throughput(Throughput::Bytes(size_bytes));
        
        group.bench_with_input(BenchmarkId::from_parameter(size_kb), size_kb, |b, &size_kb| {
            let (identity, recipient) = generate_keys();
            let data = vec![0u8; (size_kb * 1024) as usize];
            
            b.to_async(&rt).iter(|| async {
                let temp_dir = tempfile::tempdir().unwrap();
                let output_path = temp_dir.path().join("encrypted.age");
                let mut reader = data.as_slice();
                
                encrypt_reader_to_age_file(&recipient, &mut reader, &output_path)
                    .await
                    .unwrap();
            });
        });
    }
    group.finish();
}

fn bench_decrypt_age_file_to_writer(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_age_file_to_writer");
    let rt = Runtime::new().unwrap();

    for size_kb in [1024, 10240].iter() {
        let size_bytes = (size_kb * 1024) as u64;
        group.throughput(Throughput::Bytes(size_bytes));
        
        let (identity, recipient) = generate_keys();
        let data = vec![1u8; (size_kb * 1024) as usize];
        
        let temp_dir = tempfile::tempdir().unwrap();
        let encrypted_path = temp_dir.path().join(format!("encrypted_{}.age", size_kb));
        
        // Pre-encriptar para que no sea parte del tiempo de benchmark
        rt.block_on(async {
            let mut reader = data.as_slice();
            encrypt_reader_to_age_file(&recipient, &mut reader, &encrypted_path)
                .await
                .unwrap();
        });

        group.bench_with_input(BenchmarkId::from_parameter(size_kb), size_kb, |b, &_size_kb| {
            b.to_async(&rt).iter(|| async {
                let mut writer = tokio::io::sink();
                decrypt_age_file_to_writer(&identity, &encrypted_path, &mut writer)
                    .await
                    .unwrap();
            });
        });
    }
    group.finish();
}

fn bench_metadata(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata_operations");
    let rt = Runtime::new().unwrap();

    let (identity, recipient) = generate_keys();
    let metadata = FileMetadata {
        filename: Some("test_file_name_very_long_for_benchmarking.txt".to_string()),
        origin: Some("benchmark_script".to_string()),
        filesize: Some(1024 * 1024),
        extended: std::collections::HashMap::new(),
    };

    let temp_dir = tempfile::tempdir().unwrap();
    let meta_path = temp_dir.path().join("test.meta.age");

    group.bench_function("encrypt_metadata_file", |b| {
        b.to_async(&rt).iter(|| async {
            encrypt_metadata_file(&recipient, &metadata, &meta_path)
                .await
                .unwrap();
        });
    });

    // Asegurarse de que el archivo existe para decrypt_metadata_file
    rt.block_on(async {
        encrypt_metadata_file(&recipient, &metadata, &meta_path)
            .await
            .unwrap();
    });

    group.bench_function("decrypt_metadata_file", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = decrypt_metadata_file(&identity, &meta_path)
                .await
                .unwrap();
        });
    });

    group.finish();
}

fn bench_vault(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_operations");
    let rt = Runtime::new().unwrap();

    group.bench_function("create_vault", |b| {
        b.to_async(&rt).iter(|| async {
            let temp_dir = tempfile::tempdir().unwrap();
            let _ = create_vault(
                temp_dir.path(), 
                "new_vault", 
                "super_secure_password".to_string(), 
                VaultPermissions::default()
            ).await.unwrap();
        });
    });

    let temp_dir = tempfile::tempdir().unwrap();
    
    rt.block_on(async {
        create_vault(
            temp_dir.path(), 
            "existing_vault", 
            "super_secure_password".to_string(), 
            VaultPermissions {
                allow_lock_unlock: true,
                ..Default::default()
            }
        ).await.unwrap();
    });

    group.bench_function("unlock_and_lock_vault", |b| {
        b.to_async(&rt).iter(|| async {
            let mut unlocked_vaults = HashMap::new();
            unlock_vault(
                &mut unlocked_vaults, 
                temp_dir.path(), 
                "existing_vault", 
                "super_secure_password".to_string(), 
                Duration::from_secs(3600)
            ).await.unwrap();
            
            lock_vault(&mut unlocked_vaults, temp_dir.path(), "existing_vault").await.unwrap();
        });
    });

    group.finish();
}

fn bench_decrypt_age_file_range_to_writer(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt_age_file_range_to_writer");
    let rt = Runtime::new().unwrap();

    let size_kb = 10240; // 10MB file
    let (identity, recipient) = generate_keys();
    let data = vec![2u8; (size_kb * 1024) as usize];
    
    let temp_dir = tempfile::tempdir().unwrap();
    let encrypted_path = temp_dir.path().join("encrypted_range.age");
    
    // Pre-encriptar
    rt.block_on(async {
        let mut reader = data.as_slice();
        encrypt_reader_to_age_file(&recipient, &mut reader, &encrypted_path)
            .await
            .unwrap();
    });

    // Leer diferentes rangos
    let ranges = [
        (0_u64, 1024_u64 * 1024 - 1), // Primer MB
        (5_u64 * 1024 * 1024, 6_u64 * 1024 * 1024 - 1), // Un MB a la mitad
        (9_u64 * 1024 * 1024, 10_u64 * 1024 * 1024 - 1), // Último MB
    ];

    for &(start, end) in ranges.iter() {
        let read_bytes = end - start + 1;
        group.throughput(Throughput::Bytes(read_bytes));
        
        group.bench_with_input(BenchmarkId::from_parameter(format!("{}_{}", start, end)), &(start, end), |b, &(start, end)| {
            b.to_async(&rt).iter(|| async {
                let mut writer = tokio::io::sink();
                decrypt_age_file_range_to_writer(&identity, &encrypted_path, &mut writer, start, end)
                    .await
                    .unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(benches, 
    bench_encrypt_reader_to_age_file, 
    bench_decrypt_age_file_to_writer, 
    bench_decrypt_age_file_range_to_writer,
    bench_metadata,
    bench_vault
);
criterion_main!(benches);
