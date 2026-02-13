use std::process::Command;

#[test]
fn bin_version_runs() {
    let bin = env!("CARGO_BIN_EXE_secrt");
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("secrt "));
}

#[test]
fn bin_help_runs() {
    let bin = env!("CARGO_BIN_EXE_secrt");
    let out = Command::new(bin)
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("USAGE") || stderr.contains("USAGE"),
        "stdout={stdout}\nstderr={stderr}"
    );
}
