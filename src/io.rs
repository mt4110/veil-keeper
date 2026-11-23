use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Value;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, Unique(value))) = map.next_entry::<String, Unique>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(Value::Object(values))
            }
        }
        input.deserialize_any(JsonVisitor).map(Unique)
    }
}

fn open_at(dir: &File, name: &std::ffi::OsStr, flags: i32) -> io::Result<File> {
    let name = std::ffi::CString::new(name.as_bytes())?;
    // The directory descriptor pins the parent across concurrent renames.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn trusted(dir: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let info = dir.metadata()?;
    if (info.uid() == 0 || info.uid() == unsafe { libc::geteuid() }) && info.mode() & 0o022 == 0 {
        return Ok(());
    }
    Err(io::Error::other("untrusted output directory"))
}

fn open_path(path: &Path, output: bool) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::path::absolute(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("missing filename"))?;
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open("/")?;
    for part in path.parent().unwrap().components() {
        match part {
            Component::RootDir => {}
            Component::Normal(part) => {
                if output {
                    trusted(&dir)?;
                }
                dir = open_at(&dir, part, libc::O_RDONLY | libc::O_DIRECTORY)?;
            }
            _ => return Err(io::Error::other("noncanonical path")),
        }
    }
    let flags = if output {
        trusted(&dir)?;
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
    } else {
        libc::O_RDONLY | libc::O_NONBLOCK
    };
    open_at(&dir, name, flags)
}

pub fn read(path: &Path, limit: u64) -> Result<(Value, String), &'static str> {
    let file = open_path(path, false).map_err(|_| "input_unavailable")?;
    if !file.metadata().map_err(|_| "input_unavailable")?.is_file() {
        return Err("input_not_regular");
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input_unavailable")?;
    if bytes.len() as u64 > limit {
        return Err("input_too_large");
    }
    let Unique(value) = serde_json::from_slice(&bytes).map_err(|_| "invalid_json")?;
    Ok((value, format!("{:x}", Sha256::digest(bytes))))
}

pub fn save(path: &Path, value: &Value) -> io::Result<()> {
    let mut file = open_path(path, true)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()
}
