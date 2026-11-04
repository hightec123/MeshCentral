use anyhow::{Result, ensure};
use std::{collections::BTreeMap, path::Path, sync::Arc};
pub struct Bundle {
    pub hash: [u8; 48],
    pub bytes: Vec<u8>,
}
pub struct Cores {
    bundles: BTreeMap<String, Arc<Bundle>>,
}
impl Cores {
    pub fn load(directory: &Path) -> Result<Self> {
        let mut bundles = BTreeMap::new();
        for platform in ["macos", "linux", "windows"] {
            let path = directory.join(format!("{platform}.bin"));
            if path.exists() {
                let bytes = std::fs::read(path)?;
                ensure!(
                    bytes.len() >= 4 && bytes.len() <= 2 * 1024 * 1024 && bytes[..4] == [0; 4],
                    "invalid agent core bundle"
                );
                bundles.insert(
                    platform.into(),
                    Arc::new(Bundle {
                        hash: openssl::sha::sha384(&bytes),
                        bytes,
                    }),
                );
            }
        }
        Ok(Self { bundles })
    }
    pub fn for_architecture(&self, architecture: u32) -> Option<Arc<Bundle>> {
        let os = match architecture {
            3 | 4 | 43 => "windows",
            16 | 29 => "macos",
            5 | 6 | 24 | 25 | 26 | 27 | 28 | 30 | 32 | 37 | 40 => "linux",
            _ => return None,
        };
        self.bundles.get(os).cloned()
    }
    pub fn available(&self) -> bool {
        !self.bundles.is_empty()
    }
}
