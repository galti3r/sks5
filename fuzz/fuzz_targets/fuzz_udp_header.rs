#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz UdpHeader::parse with arbitrary bytes — must never panic
    if let Ok((header, consumed)) = sks5::socks::protocol::UdpHeader::parse(data) {
        // If parse succeeds, round-trip should produce valid output
        let serialized = header.serialize();
        let (reparsed, _) = sks5::socks::protocol::UdpHeader::parse(&serialized)
            .expect("round-trip parse should succeed");
        assert_eq!(reparsed.frag, header.frag);
        assert_eq!(reparsed.target.port(), header.target.port());
        // Verify consumed <= data.len()
        assert!(consumed <= data.len());
    }
});
