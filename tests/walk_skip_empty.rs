//! Skip entries that are all empty skip nothing, so SKIP stays unset (it
//! reads as "no Full Disk Access" otherwise). `walk::SKIP` is global: own binary.

use fsearch::walk;

#[test]
fn nothing_to_skip_leaves_skip_unset() {
    walk::set_skip(vec![Vec::new(), Vec::new()]);
    assert!(walk::SKIP.get().is_none());
    assert!(!walk::blocked(b"/anything"));
}
