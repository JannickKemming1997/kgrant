use std::path::{Path, PathBuf};

const SOCKET_NAME: &str = "org.keepassxc.KeePassXC.BrowserServer";

/// Where KeePassXC listens, if `$XDG_RUNTIME_DIR` is set.
///
/// Native builds use `app/org.keepassxc.KeePassXC/<name>`; the plain
/// runtime-dir path is the fallback. Flatpak builds differ (unverified).
pub fn default_socket_path() -> Option<PathBuf> {
    Some(socket_path_in(&PathBuf::from(std::env::var_os(
        "XDG_RUNTIME_DIR",
    )?)))
}

fn socket_path_in(runtime: &Path) -> PathBuf {
    let nested = runtime
        .join("app/org.keepassxc.KeePassXC")
        .join(SOCKET_NAME);
    if nested.exists() {
        nested
    } else {
        runtime.join(SOCKET_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_is_in_the_runtime_directory_by_default() {
        let runtime = tempfile::tempdir().unwrap();
        assert_eq!(
            socket_path_in(runtime.path()),
            runtime.path().join(SOCKET_NAME)
        );
    }

    #[test]
    fn socket_in_the_app_subdirectory_is_preferred_when_it_exists() {
        let runtime = tempfile::tempdir().unwrap();
        let nested = runtime.path().join("app/org.keepassxc.KeePassXC");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join(SOCKET_NAME), "").unwrap();
        assert_eq!(socket_path_in(runtime.path()), nested.join(SOCKET_NAME));
    }
}
