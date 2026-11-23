use bstr::ByteSlice;
use gix_testtools::TestResult;

#[test]
fn msys_arguments_are_literal() -> TestResult {
    if gix_testtools::run_in_isolated_process()? {
        return Ok(());
    }
    let printf = gix_path::env::installation_program("printf").expect("Git for Windows provides MSYS printf");
    let root = gix_testtools::tempfile::tempdir()?;
    let _cwd = gix_testtools::set_current_dir(root.path())?;
    std::fs::write(root.path().join("glob-target"), [])?;
    let arguments = [
        "{-oBatchMode=yes,x}",
        "'{-oBatchMode=yes,x}'",
        "'team/repo.git;echo harmless'",
        "git-upload-pack 'team/repo.git;echo harmless'",
        "*",
        "?",
        "~",
        "",
        "a b",
        "a\tb",
        "a\nb",
        "a'b",
        "a\"b",
        r"a\b\",
        r#"a\"b"#,
        "日本語",
    ];
    let output = gix_command::prepare(printf)
        .arg("<%s>\n")
        .args(arguments)
        .spawn()?
        .wait_with_output()?;
    assert!(output.status.success(), "the MSYS program completes successfully");
    let mut expected = String::new();
    for arg in arguments {
        expected.push('<');
        expected.push_str(arg);
        expected.push_str(">\n");
    }
    assert_eq!(
        output.stdout.as_bstr(),
        expected.as_bytes().as_bstr(),
        "the runtime must neither remove quotes nor expand arguments"
    );
    Ok(())
}

#[test]
fn msys_shell_preserves_positional_arguments() -> TestResult {
    if gix_testtools::run_in_isolated_process()? {
        return Ok(());
    }
    let output = gix_command::prepare(r#"printf '<%s>\n' "$@""#)
        .with_shell()
        .args(["{first,second}", "'repo;echo harmless'", r"a\b\"])
        .spawn()?
        .wait_with_output()?;
    assert!(output.status.success(), "the shell completes successfully");
    assert_eq!(
        output.stdout.as_bstr(),
        b"<{first,second}>\n<'repo;echo harmless'>\n<a\\b\\>\n".as_bstr(),
        "positional arguments arrive literally through the Windows shell launch"
    );
    Ok(())
}

#[test]
fn renamed_msys_program_is_detected_after_path_lookup() -> TestResult {
    if gix_testtools::run_in_isolated_process()? {
        return Ok(());
    }
    let printf = gix_path::env::installation_program("printf").expect("Git for Windows provides MSYS printf");
    // Rename the executable while leaving its runtime and support DLLs available on PATH.
    let root = gix_testtools::tempfile::tempdir()?;
    let renamed = root.path().join("unrecognized.exe");
    std::fs::copy(&printf, &renamed)?;
    let path = std::env::join_paths([root.path(), printf.parent().expect("printf is inside a bin directory")])?;
    let output = gix_command::prepare("unrecognized")
        .env("PATH", path)
        .args(["%s", "{first,second}"])
        .spawn()?
        .wait_with_output()?;
    assert!(
        output.status.success(),
        "the renamed MSYS program completes successfully"
    );
    assert_eq!(
        output.stdout.as_bstr(),
        "{first,second}",
        "runtime detection uses the resolved executable rather than its basename"
    );
    Ok(())
}

#[test]
fn msys_ssh_feature_probe_cannot_expand_options() -> TestResult {
    if gix_testtools::run_in_isolated_process()? {
        return Ok(());
    }
    let ssh = gix_path::env::installation_program("ssh").expect("Git for Windows provides MSYS ssh");
    let output = gix_command::prepare(ssh)
        .args(["-F", "/dev/null", "-G", "{-oBatchMode=yes,x}"])
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()?;
    assert!(
        !output.status.success(),
        "ssh must reject the literal invalid hostname instead of accepting expanded options"
    );
    assert!(
        output.stderr.contains_str("hostname contains invalid characters"),
        "the host reaches OpenSSH literally, without a connection attempt"
    );
    Ok(())
}

#[test]
fn native_program_retains_standard_argument_encoding() -> TestResult {
    if gix_testtools::run_in_isolated_process()? {
        return Ok(());
    }
    let arguments = ["{first,second}", "'repo'", r"a\b\", "a\"b", ""];
    let cmd = std::process::Command::try_from(gix_command::prepare(std::env::current_exe()?).args(arguments))?;
    assert_eq!(
        cmd.get_args().collect::<Vec<_>>(),
        arguments.map(std::ffi::OsStr::new),
        "native programs keep Rust's standard Windows argument quoting"
    );
    Ok(())
}
