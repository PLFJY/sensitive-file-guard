use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevelopmentBundleLayout {
    root: PathBuf,
    extension_bundle_id: String,
}

impl DevelopmentBundleLayout {
    pub fn new(
        root: impl Into<PathBuf>,
        extension_bundle_id: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let extension_bundle_id = extension_bundle_id.into();
        anyhow::ensure!(
            valid_bundle_identifier(&extension_bundle_id),
            "invalid system extension bundle identifier"
        );
        Ok(Self {
            root: root.into(),
            extension_bundle_id,
        })
    }

    pub fn app(&self) -> &Path {
        &self.root
    }
    pub fn app_contents(&self) -> PathBuf {
        self.root.join("Contents")
    }
    pub fn app_executable(&self) -> PathBuf {
        self.app_contents().join("MacOS/SensitiveFileGuard")
    }
    pub fn app_info_plist(&self) -> PathBuf {
        self.app_contents().join("Info.plist")
    }
    pub fn extension(&self) -> PathBuf {
        self.app_contents()
            .join("Library/SystemExtensions")
            .join(format!("{}.systemextension", self.extension_bundle_id))
    }
    pub fn extension_executable(&self) -> PathBuf {
        self.extension().join("Contents/MacOS/guard-es")
    }
    pub fn extension_info_plist(&self) -> PathBuf {
        self.extension().join("Contents/Info.plist")
    }
}

pub fn valid_bundle_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').count() >= 2
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_required_nested_bundle_paths() {
        let layout = DevelopmentBundleLayout::new(
            "/tmp/Sensitive File Guard.app",
            "top.plfjy.SensitiveFileGuard.guard-es",
        )
        .unwrap();
        assert_eq!(
            layout.app_executable(),
            PathBuf::from("/tmp/Sensitive File Guard.app/Contents/MacOS/SensitiveFileGuard")
        );
        assert_eq!(layout.extension_executable(), PathBuf::from("/tmp/Sensitive File Guard.app/Contents/Library/SystemExtensions/top.plfjy.SensitiveFileGuard.guard-es.systemextension/Contents/MacOS/guard-es"));
        assert_eq!(layout.extension_info_plist(), PathBuf::from("/tmp/Sensitive File Guard.app/Contents/Library/SystemExtensions/top.plfjy.SensitiveFileGuard.guard-es.systemextension/Contents/Info.plist"));
    }

    #[test]
    fn rejects_paths_disguised_as_bundle_identifiers() {
        for value in [
            "",
            "guard-es",
            "../guard-es",
            "io.github.guard/es",
            "io..guard",
        ] {
            assert!(!valid_bundle_identifier(value), "accepted {value:?}");
        }
    }
}
