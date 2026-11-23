use std::{
    ffi::{OsStr, OsString},
    os::windows::{ffi::OsStrExt, ffi::OsStringExt, process::CommandExt},
    process::Command,
};

use gix_error::{ErrorExt, Result, message};

/// Apply the selected executable's argument syntax before configuring environment and stdio.
pub(super) fn quote_arguments(cmd: Command, force_posix: bool) -> Result<Command> {
    if !cmd.get_args().any(needs_quoting) {
        return Ok(cmd);
    }
    if !force_posix {
        let image = match std::fs::read(cmd.get_program()) {
            Ok(image) => image,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
                ) =>
            {
                return Ok(cmd);
            }
            Err(err) => return Err(err.and_raise(message!("Could not inspect executable {:?}", cmd.get_program()))),
        };
        if imports_posix_runtime(&image) != Some(true) {
            return Ok(cmd);
        }
    }
    let mut quoted = Command::new(cmd.get_program());
    for arg in cmd.get_args() {
        match quote(arg) {
            Some(arg) => quoted.raw_arg(arg),
            None => quoted.arg(arg),
        };
    }
    Ok(quoted)
}

/// MSYS2/Cygwin parse a native command line again, expanding unquoted arguments.
/// Double quotes suppress expansion and preserve single quotes meant for a remote shell.
fn quote(arg: &OsStr) -> Option<OsString> {
    if !needs_quoting(arg) {
        return None;
    }
    let mut quoted = vec![u16::from(b'"')];
    for c in arg.encode_wide() {
        if c == u16::from(b'\\') || c == u16::from(b'"') {
            quoted.push(u16::from(b'\\'));
        }
        quoted.push(c);
    }
    quoted.push(u16::from(b'"'));
    Some(OsString::from_wide(&quoted))
}

fn needs_quoting(arg: &OsStr) -> bool {
    arg.is_empty()
        || arg.encode_wide().any(|c| {
            u8::try_from(c).ok().is_some_and(|c| {
                c.is_ascii_whitespace() || matches!(c, b'"' | b'\'' | b'*' | b'?' | b'[' | b'\\' | b'{' | b'~')
            })
        })
}

/// Read PE import names rather than guessing from the executable's name or installation path.
fn imports_posix_runtime(image: &[u8]) -> Option<bool> {
    fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?))
    }
    fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
    }
    if image.get(..2)? != b"MZ" {
        return None;
    }
    let pe = image.get(u32_at(image, 0x3c)? as usize..)?;
    if pe.get(..4)? != b"PE\0\0" {
        return None;
    }
    let optional_size = usize::from(u16_at(pe, 20)?);
    let optional = pe.get(24..24usize.checked_add(optional_size)?)?;
    let directory = match u16_at(optional, 0)? {
        0x10b => 104, // PE32 import directory.
        0x20b => 120, // PE32+ import directory.
        _ => return None,
    };
    let import_rva = u32_at(optional, directory)?;
    let import_size = u32_at(optional, directory + 4)?;
    if import_rva == 0 {
        return Some(false);
    }
    let section_start = 24usize.checked_add(optional_size)?;
    let section_size = usize::from(u16_at(pe, 6)?).checked_mul(40)?;
    let sections = pe.get(section_start..section_start.checked_add(section_size)?)?;
    let file_offset = |rva: u32| -> Option<usize> {
        if rva < u32_at(optional, 60)? {
            return Some(rva as usize);
        }
        sections.as_chunks::<40>().0.iter().find_map(|section| {
            let within = rva.checked_sub(u32_at(section, 12)?)?;
            (within < u32_at(section, 16)?)
                .then(|| u32_at(section, 20)?.checked_add(within).map(|offset| offset as usize))?
        })
    };
    for offset in (0..import_size).step_by(20) {
        let descriptor = image.get(file_offset(import_rva.checked_add(offset)?)?..)?;
        let name_rva = u32_at(descriptor, 12)?;
        if name_rva == 0 {
            return Some(false);
        }
        let name = image.get(file_offset(name_rva)?..)?;
        let name = name.get(..name.iter().position(|&c| c == 0)?)?;
        if name.eq_ignore_ascii_case(b"msys-2.0.dll") || name.eq_ignore_ascii_case(b"cygwin1.dll") {
            return Some(true);
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::imports_posix_runtime;

    fn image(magic: u16, dll: &[u8]) -> Vec<u8> {
        let mut image = vec![0; 0x500];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        let pe = &mut image[0x40..];
        pe[..4].copy_from_slice(b"PE\0\0");
        pe[6..8].copy_from_slice(&1u16.to_le_bytes());
        let size = if magic == 0x10b { 224 } else { 240 };
        pe[20..22].copy_from_slice(&(size as u16).to_le_bytes());
        pe[24..26].copy_from_slice(&magic.to_le_bytes());
        let directory = 24 + if magic == 0x10b { 104 } else { 120 };
        pe[directory..directory + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[directory + 4..directory + 8].copy_from_slice(&40u32.to_le_bytes());
        let section = &mut pe[24 + size..];
        section[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
        section[16..20].copy_from_slice(&0x300u32.to_le_bytes());
        section[20..24].copy_from_slice(&0x200u32.to_le_bytes());
        image[0x20c..0x210].copy_from_slice(&0x1040u32.to_le_bytes());
        image[0x240..0x240 + dll.len()].copy_from_slice(dll);
        image
    }

    #[test]
    fn runtime_detection_uses_imports_for_both_pe_formats() {
        for magic in [0x10b, 0x20b] {
            for dll in [b"msys-2.0.dll".as_slice(), b"CYGWIN1.DLL"] {
                assert_eq!(imports_posix_runtime(&image(magic, dll)), Some(true));
            }
            let mut native = image(magic, b"kernel32.dll");
            native[0x300..0x30c].copy_from_slice(b"msys-2.0.dll");
            assert_eq!(
                imports_posix_runtime(&native),
                Some(false),
                "a runtime name outside the import table does not identify a POSIX executable"
            );
        }
    }

    #[test]
    fn malformed_images_do_not_panic() {
        let valid = image(0x20b, b"msys-2.0.dll");
        for len in 0..valid.len() {
            imports_posix_runtime(&valid[..len]);
        }
        let mut invalid = valid;
        invalid[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            imports_posix_runtime(&invalid),
            None,
            "invalid offsets cannot leave the image"
        );
    }
}
