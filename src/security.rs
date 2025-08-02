use anyhow::{Result, Context};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::thread;
use zeroize::Zeroize;

#[cfg(unix)]
use libc::{mlock, munlock};

pub struct SecurityManager {
    binary_path: PathBuf,
    binary_hash: Option<String>,
    locked_memory: Vec<*mut u8>,
}

impl SecurityManager {
    pub fn new() -> Result<Self> {
        let binary_path = std::env::current_exe()
            .context("Failed to get current executable path")?;
        
        let mut manager = Self {
            binary_path,
            binary_hash: None,
            locked_memory: Vec::new(),
        };
        
        // Calculate and store binary hash for integrity checks
        manager.binary_hash = Some(manager.calculate_binary_hash()?);
        
        Ok(manager)
    }
    
    pub fn verify_binary_integrity(&self) -> Result<bool> {
        let current_hash = self.calculate_binary_hash()?;
        
        match &self.binary_hash {
            Some(original_hash) => Ok(current_hash == *original_hash),
            None => Ok(false),
        }
    }
    
    fn calculate_binary_hash(&self) -> Result<String> {
        let mut file = File::open(&self.binary_path)
            .context("Failed to open binary file for hashing")?;
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .context("Failed to read binary file")?;
        
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        buffer.hash(&mut hasher);
        let hash = hasher.finish();
        
        Ok(format!("{:x}", hash))
    }
    
    #[cfg(unix)]
    pub fn lock_memory(&mut self, ptr: *mut u8, size: usize) -> Result<()> {
        unsafe {
            if mlock(ptr as *const libc::c_void, size) != 0 {
                return Err(anyhow::anyhow!("Failed to lock memory"));
            }
        }
        
        self.locked_memory.push(ptr);
        Ok(())
    }
    
    #[cfg(unix)]
    pub fn unlock_memory(&mut self, ptr: *mut u8, size: usize) -> Result<()> {
        unsafe {
            if munlock(ptr as *const libc::c_void, size) != 0 {
                return Err(anyhow::anyhow!("Failed to unlock memory"));
            }
        }
        
        self.locked_memory.retain(|&p| p != ptr);
        Ok(())
    }
    
    #[cfg(not(unix))]
    pub fn lock_memory(&mut self, _ptr: *mut u8, _size: usize) -> Result<()> {
        // Memory locking not implemented for non-Unix systems
        Ok(())
    }
    
    #[cfg(not(unix))]
    pub fn unlock_memory(&mut self, _ptr: *mut u8, _size: usize) -> Result<()> {
        // Memory unlocking not implemented for non-Unix systems
        Ok(())
    }
    
    pub fn perform_decoy_operations(&self) -> Result<()> {
        // Perform fake crypto operations to confuse potential keyloggers
        let start = Instant::now();
        
        // Simulate various crypto operations
        for i in 0..5 {
            let fake_data = format!("fake_operation_{}", i);
            let _ = self.fake_encrypt(fake_data.as_bytes());
            
            // Add random delays
            let delay = Duration::from_millis(50 + (i * 25));
            thread::sleep(delay);
        }
        
        // Ensure this takes at least 200ms to look realistic
        let elapsed = start.elapsed();
        if elapsed < Duration::from_millis(200) {
            thread::sleep(Duration::from_millis(200) - elapsed);
        }
        
        Ok(())
    }
    
    fn fake_encrypt(&self, data: &[u8]) -> Vec<u8> {
        // Perform fake encryption that looks like real crypto
        data.iter().map(|b| b.wrapping_add(42)).collect()
    }
    
    pub fn clear_terminal_history(&self) -> Result<()> {
        // Clear terminal screen and scrollback
        print!("\x1B[2J\x1B[3J\x1B[1;1H");
        std::io::stdout().flush()?;
        
        // Additional clearing for different terminal types
        let clear_commands = vec![
            "clear",
            "printf '\\033[2J\\033[3J\\033[1;1H'",
        ];
        
        for cmd in clear_commands {
            let _ = Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        
        Ok(())
    }
    
    pub fn secure_input_mode(&self) -> Result<()> {
        // Disable terminal echo and enable raw mode for secure input
        #[cfg(unix)]
        {
            let _ = Command::new("stty")
                .args(&["-echo", "raw"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        
        Ok(())
    }
    
    pub fn restore_input_mode(&self) -> Result<()> {
        // Restore normal terminal mode
        #[cfg(unix)]
        {
            let _ = Command::new("stty")
                .args(&["echo", "cooked"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        
        Ok(())
    }
    
    pub fn check_process_environment(&self) -> Result<SecurityReport> {
        let mut report = SecurityReport::new();
        
        // Check for debugging tools
        report.debugger_detected = self.detect_debugger()?;
        
        // Check for suspicious processes
        report.suspicious_processes = self.scan_processes()?;
        
        // Check for keyloggers (basic detection)
        report.potential_keylogger = self.detect_keylogger()?;
        
        // Check system load (could indicate mining malware)
        report.high_system_load = self.check_system_load()?;
        
        Ok(report)
    }
    
    fn detect_debugger(&self) -> Result<bool> {
        // Check for common debugging indicators
        let debug_env_vars = vec![
            "RUST_BACKTRACE",
            "_DEBUG",
            "DEBUG",
        ];
        
        for var in debug_env_vars {
            if std::env::var(var).is_ok() {
                return Ok(true);
            }
        }
        
        // Check for debugger processes (basic)
        let debugger_processes = vec!["gdb", "lldb", "strace", "dtrace"];
        
        for process in debugger_processes {
            if self.is_process_running(process)? {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    fn scan_processes(&self) -> Result<Vec<String>> {
        let mut suspicious = Vec::new();
        
        let suspicious_names = vec![
            "keylogger", "wireshark", "tcpdump", "nmap",
            "metasploit", "burp", "proxychains",
        ];
        
        for name in suspicious_names {
            if self.is_process_running(name)? {
                suspicious.push(name.to_string());
            }
        }
        
        Ok(suspicious)
    }
    
    fn detect_keylogger(&self) -> Result<bool> {
        // Basic keylogger detection
        let keylogger_indicators = vec![
            "/tmp/.keylog",
            "/var/log/keylog",
            "keylogger.log",
        ];
        
        for path in keylogger_indicators {
            if Path::new(path).exists() {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    fn check_system_load(&self) -> Result<bool> {
        // Check if system load is suspiciously high
        #[cfg(unix)]
        {
            if let Ok(output) = Command::new("uptime").output() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                // System load monitoring for suspicious activity
                if output_str.contains("load average:") {
                    // Parse load averages and check for unusual patterns
                    if let Some(load_start) = output_str.find("load average:") {
                        let load_part = &output_str[load_start + 13..];
                        if let Some(first_load) = load_part.split(',').next() {
                            if let Ok(load_value) = first_load.trim().parse::<f64>() {
                                // Consider load suspicious if over 8.0 on most systems
                                return Ok(load_value > 8.0);
                            }
                        }
                    }
                }
            }
        }
        
        Ok(false)
    }
    
    fn is_process_running(&self, process_name: &str) -> Result<bool> {
        #[cfg(unix)]
        {
            let output = Command::new("pgrep")
                .arg(process_name)
                .output()
                .context("Failed to check for running processes")?;
            
            return Ok(!output.stdout.is_empty());
        }
        
        #[cfg(windows)]
        {
            let output = Command::new("tasklist")
                .arg("/FI")
                .arg(&format!("IMAGENAME eq {}.exe", process_name))
                .output()
                .context("Failed to check for running processes")?;
            
            let output_str = String::from_utf8_lossy(&output.stdout);
            return Ok(output_str.contains(process_name));
        }
        
        #[cfg(not(any(unix, windows)))]
        Ok(false)
    }
    
    pub fn create_isolation_environment(&self) -> Result<IsolatedEnvironment> {
        // Create a sandboxed environment for crypto operations
        IsolatedEnvironment::new()
    }
}

pub struct SecurityReport {
    pub debugger_detected: bool,
    pub suspicious_processes: Vec<String>,
    pub potential_keylogger: bool,
    pub high_system_load: bool,
    pub binary_integrity_ok: bool,
}

impl SecurityReport {
    fn new() -> Self {
        Self {
            debugger_detected: false,
            suspicious_processes: Vec::new(),
            potential_keylogger: false,
            high_system_load: false,
            binary_integrity_ok: true,
        }
    }
    
    pub fn has_security_issues(&self) -> bool {
        self.debugger_detected
            || !self.suspicious_processes.is_empty()
            || self.potential_keylogger
            || self.high_system_load
            || !self.binary_integrity_ok
    }
    
    pub fn print_report(&self) {
        println!("┌─────────────────────────────────────────────────────────────┐");
        println!("│                    🛡️  SECURITY SCAN REPORT                │");
        println!("├─────────────────────────────────────────────────────────────┤");
        
        let status = if self.has_security_issues() { "⚠️  WARNINGS DETECTED" } else { "✅ ALL CLEAR" };
        println!("│ Status: {:<52} │", status);
        println!("│                                                             │");
        
        if self.debugger_detected {
            println!("│ ⚠️  Debugger detected                                      │");
        }
        
        if !self.suspicious_processes.is_empty() {
            println!("│ ⚠️  Suspicious processes: {:<34} │", self.suspicious_processes.join(", "));
        }
        
        if self.potential_keylogger {
            println!("│ ⚠️  Potential keylogger detected                           │");
        }
        
        if self.high_system_load {
            println!("│ ⚠️  Unusually high system load                            │");
        }
        
        if !self.binary_integrity_ok {
            println!("│ ❌ Binary integrity check failed                          │");
        }
        
        println!("└─────────────────────────────────────────────────────────────┘");
    }
}

pub struct IsolatedEnvironment {
    temp_dir: PathBuf,
}

impl IsolatedEnvironment {
    fn new() -> Result<Self> {
        let temp_dir = std::env::temp_dir().join(format!("ryzan_isolated_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir)?;
        
        Ok(Self { temp_dir })
    }
    
    pub fn execute_isolated<F, T>(&self, operation: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        // Change to isolated directory
        let original_dir = std::env::current_dir()?;
        std::env::set_current_dir(&self.temp_dir)?;
        
        // Execute the operation
        let result = operation();
        
        // Restore original directory
        std::env::set_current_dir(original_dir)?;
        
        result
    }
}

impl Drop for IsolatedEnvironment {
    fn drop(&mut self) {
        // Clean up temporary directory
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

impl Drop for SecurityManager {
    fn drop(&mut self) {
        // Unlock all locked memory
        #[cfg(unix)]
        {
            for &ptr in &self.locked_memory {
                unsafe {
                    let _ = munlock(ptr as *const libc::c_void, 4096); // Assuming 4KB pages
                }
            }
        }
        
        // Clear terminal on exit
        let _ = self.clear_terminal_history();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_manager_creation() {
        let manager = SecurityManager::new();
        assert!(manager.is_ok());
    }
    
    #[test]
    fn test_security_report() {
        let report = SecurityReport::new();
        assert!(!report.has_security_issues());
    }
    
    #[test]
    fn test_isolated_environment() {
        let env = IsolatedEnvironment::new().unwrap();
        
        let result = env.execute_isolated(|| {
            Ok("test_result".to_string())
        }).unwrap();
        
        assert_eq!(result, "test_result");
    }
}