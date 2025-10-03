// comment.root.rs - Root-level setup for comment extension
// This runs before privileges are dropped to ensure proper file ownership

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
use libc::{chown, getpwnam, getgrnam};

#[cfg(unix)]
fn get_www_data_uid() -> Result<libc::uid_t, String> {
    unsafe {
        let passwd = getpwnam(b"www-data\0".as_ptr() as *const libc::c_char);
        if passwd.is_null() {
            return Err("www-data user not found".to_string());
        }
        Ok((*passwd).pw_uid)
    }
}

#[cfg(unix)]
fn get_www_data_gid() -> Result<libc::gid_t, String> {
    unsafe {
        let group = getgrnam(b"www-data\0".as_ptr() as *const libc::c_char);
        if group.is_null() {
            return Err("www-data group not found".to_string());
        }
        Ok((*group).gr_gid)
    }
}

#[cfg(unix)]
fn chown_path(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> Result<(), String> {
    use std::ffi::CString;
    
    let path_cstr = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|e| format!("Invalid path: {}", e))?;
    
    unsafe {
        if chown(path_cstr.as_ptr(), uid, gid) != 0 {
            return Err(format!("Failed to chown {:?}", path));
        }
    }
    Ok(())
}

pub fn setup_comment_directories() -> Result<(), String> {
    #[cfg(not(unix))]
    {
        return Err("Root extensions are only supported on Unix systems".to_string());
    }
    
    #[cfg(unix)]
    {
        let www_data_uid = get_www_data_uid()?;
        let www_data_gid = get_www_data_gid()?;
        
        // Create the comments directory
        let comments_dir = Path::new("/var/spool/easypeas/comments");
        if !comments_dir.exists() {
            fs::create_dir_all(comments_dir)
                .map_err(|e| format!("Failed to create comments directory: {}", e))?;
        }
        
        // Set ownership to www-data
        chown_path(comments_dir, www_data_uid, www_data_gid)?;
        
        // Set permissions to 755 (rwxr-xr-x)
        let mut perms = fs::metadata(comments_dir)
            .map_err(|e| format!("Failed to get metadata for comments directory: {}", e))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(comments_dir, perms)
            .map_err(|e| format!("Failed to set permissions for comments directory: {}", e))?;
        
        // Create the comments file if it doesn't exist
        let comments_file = comments_dir.join("in");
        if !comments_file.exists() {
            fs::write(&comments_file, "")
                .map_err(|e| format!("Failed to create comments file: {}", e))?;
        }
        
        // Set ownership of the comments file to www-data
        chown_path(&comments_file, www_data_uid, www_data_gid)?;
        
        // Set permissions to 644 (rw-r--r--)
        let mut perms = fs::metadata(&comments_file)
            .map_err(|e| format!("Failed to get metadata for comments file: {}", e))?
            .permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&comments_file, perms)
            .map_err(|e| format!("Failed to set permissions for comments file: {}", e))?;
        
        Ok(())
    }
}
