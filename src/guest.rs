use serde_json::Value;

#[cfg(target_os = "linux")]
mod linux;

pub fn run(mode: &str) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    return linux::run(mode);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mode;
        Err("dedicated Linux VM required".into())
    }
}

pub fn sender(args: &[Option<&str>]) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    return linux::sender(args);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        Err("dedicated Linux VM required".into())
    }
}
