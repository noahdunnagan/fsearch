//! Small OS-specific operations shared by the engine and CLI.

#[derive(Clone, Copy)]
pub enum Priority {
    Interactive,
    Initiated,
}

pub fn set_priority(priority: Priority) {
    #[cfg(target_os = "macos")]
    unsafe {
        let qos = match priority {
            Priority::Interactive => libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE,
            Priority::Initiated => libc::qos_class_t::QOS_CLASS_USER_INITIATED,
        };
        libc::pthread_set_qos_class_self_np(qos, 0);
    }
    #[cfg(windows)]
    let _ = priority;
}
