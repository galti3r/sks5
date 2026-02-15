#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut cursor = std::io::Cursor::new(data.to_vec());
        let _ = sks5::socks::protocol::read_greeting(&mut cursor).await;
    });
});
