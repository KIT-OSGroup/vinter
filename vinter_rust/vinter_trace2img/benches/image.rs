use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use tempfile::NamedTempFile;
use vinter_trace2img::{MemoryImage, MemoryImageMmap, MemoryImageVec};

fn bench_images_clone(c: &mut Criterion) {
    let MB = 1024 * 1024;
    let mut group = c.benchmark_group("MemoryImage clone");
    for size in [5 * MB, 100 * MB].iter() {
        macro_rules! bench {
            ($name: expr, $type: ty) => {
                group.bench_with_input(BenchmarkId::new($name, size), size, |b, size| {
                    let mut image = <$type as MemoryImage>::new(*size).unwrap();
                    image.fill(0xFF);
                    b.iter_batched_ref(|| (), |_| image.try_clone().unwrap(), BatchSize::LargeInput)
                });
            };
        }

        bench!("mmap", MemoryImageMmap);
        bench!("Vec", MemoryImageVec);
    }
    group.finish();
}

fn bench_images_persist(c: &mut Criterion) {
    let MB = 1024 * 1024;
    let mut group = c.benchmark_group("MemoryImage persist");
    for size in [5 * MB, 100 * MB].iter() {
        macro_rules! bench {
            ($name: expr, $type: ty) => {
                group.bench_with_input(BenchmarkId::new($name, size), size, |b, size| {
                    let mut image = <$type as MemoryImage>::new(*size).unwrap();
                    image.fill(0xFF);
                    b.iter_batched_ref(
                        || NamedTempFile::new_in(std::env::current_dir().unwrap()).unwrap(),
                        |f| {
                            image.persist(f.as_file_mut()).unwrap();
                        },
                        BatchSize::LargeInput,
                    )
                });
            };
        }

        bench!("mmap", MemoryImageMmap);
        bench!("Vec", MemoryImageVec);
    }
    group.finish();
}

criterion_group!(benches, bench_images_clone, bench_images_persist);
criterion_main!(benches);
