#[cfg(target_os = "macos")]
#[path = "cli/macos.rs"]
mod cli;
#[cfg(windows)]
#[path = "cli/windows.rs"]
mod cli;
mod protocol;
#[cfg(target_os = "macos")]
mod server;

#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("fsearch currently supports macOS and Windows");

fn main() {
    cli::main();
}
