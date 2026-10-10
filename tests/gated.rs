//! The consent-gated folders, however home is written.

#[test]
fn gated_folders_have_no_double_slash() {
    for home in ["/Users/me", "/Users/me/"] {
        let g = fsearch::gated(home);
        assert!(g.contains(&b"/Users/me/Desktop".to_vec()), "{home}");
        assert!(
            !g.iter().any(|p| p.windows(2).any(|w| w == b"//")),
            "{home}: {:?}",
            g.iter().map(|p| String::from_utf8_lossy(p)).collect::<Vec<_>>()
        );
    }
}
