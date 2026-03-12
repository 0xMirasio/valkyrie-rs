//pub mod fileloader;
pub mod rawloader;
pub mod syscall;

#[macro_export]
macro_rules! rm_file_if_exists {
    ($filepath:expr) => {{
        match std::fs::remove_file($filepath) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }};
}
