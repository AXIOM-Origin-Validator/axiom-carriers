//! Maildir Handler
//!
//! Handles reading from and writing to Maildir format directories.
//!
//! Maildir structure:
//! ```text
//! maildir/
//! ├── new/     ← New unread messages
//! ├── cur/     ← Read/processed messages
//! └── tmp/     ← Temporary files during delivery
//! ```

use crate::error::AntieError;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info};

/// Maildir handler
pub struct Maildir {
    /// Base path
    base: PathBuf,
    
    /// Path to new/ directory
    new_dir: PathBuf,
    
    /// Path to cur/ directory
    cur_dir: PathBuf,
    
    /// Path to tmp/ directory
    tmp_dir: PathBuf,
}

impl Maildir {
    /// Create or open a Maildir
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, AntieError> {
        let base = path.as_ref().to_path_buf();
        let new_dir = base.join("new");
        let cur_dir = base.join("cur");
        let tmp_dir = base.join("tmp");
        
        // Create directories if they don't exist
        fs::create_dir_all(&new_dir).await?;
        fs::create_dir_all(&cur_dir).await?;
        fs::create_dir_all(&tmp_dir).await?;
        
        info!("Opened Maildir at {}", base.display());
        
        Ok(Self {
            base,
            new_dir,
            cur_dir,
            tmp_dir,
        })
    }
    
    /// List all new messages
    pub async fn list_new(&self) -> Result<Vec<PathBuf>, AntieError> {
        let mut messages = Vec::new();
        
        let mut entries = fs::read_dir(&self.new_dir).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                messages.push(path);
            }
        }
        
        debug!("Found {} new messages in {}", messages.len(), self.new_dir.display());
        Ok(messages)
    }
    
    /// Read a message file
    pub async fn read_message(&self, path: &Path) -> Result<Vec<u8>, AntieError> {
        let content = fs::read(path).await?;
        debug!("Read message: {} ({} bytes)", path.display(), content.len());
        Ok(content)
    }
    
    /// Move message from new/ to cur/ (mark as processed)
    pub async fn mark_processed(&self, path: &Path) -> Result<PathBuf, AntieError> {
        let filename = path.file_name()
            .ok_or_else(|| AntieError::MaildirError("Invalid filename".into()))?;
        
        // Add :2,S flag to indicate seen
        let new_filename = format!("{}:2,S", filename.to_string_lossy());
        let dest = self.cur_dir.join(new_filename);
        
        fs::rename(path, &dest).await?;
        debug!("Moved message to cur/: {}", dest.display());
        
        Ok(dest)
    }
    
    /// Write a new message to the Maildir
    pub async fn write_message(&self, content: &[u8]) -> Result<PathBuf, AntieError> {
        // Generate unique filename: timestamp.pid.hostname
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_micros();
        let pid = std::process::id();
        let hostname = "localhost";
        let unique = uuid::Uuid::new_v4();
        
        let filename = format!("{}.{}.{}.{}", timestamp, pid, hostname, unique);
        
        // Write to tmp/ first
        let tmp_path = self.tmp_dir.join(&filename);
        fs::write(&tmp_path, content).await?;
        
        // Then move to new/
        let new_path = self.new_dir.join(&filename);
        fs::rename(&tmp_path, &new_path).await?;
        
        info!("Wrote message: {}", new_path.display());
        Ok(new_path)
    }
    
    /// Get base path
    pub fn path(&self) -> &Path {
        &self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_maildir_operations() {
        let dir = tempdir().unwrap();
        let maildir = Maildir::open(dir.path()).await.unwrap();
        
        // Initially empty
        let messages = maildir.list_new().await.unwrap();
        assert!(messages.is_empty());
        
        // Write a message
        let content = b"Test message content";
        let path = maildir.write_message(content).await.unwrap();
        assert!(path.exists());
        
        // Should appear in new
        let messages = maildir.list_new().await.unwrap();
        assert_eq!(messages.len(), 1);
        
        // Read it back
        let read_content = maildir.read_message(&messages[0]).await.unwrap();
        assert_eq!(read_content, content);
        
        // Mark as processed
        let cur_path = maildir.mark_processed(&messages[0]).await.unwrap();
        assert!(cur_path.exists());
        
        // Should be gone from new
        let messages = maildir.list_new().await.unwrap();
        assert!(messages.is_empty());
    }
}
