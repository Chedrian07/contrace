from pathlib import Path

from contrace.config import cli_overrides_from_args, load_file_config, resolve_config


class Args:
    guest_arch = None
    memory = None
    cpus = None
    workdir = None
    keep_workdir = False
    config = None
    port = ["4444:31337"]
    trace = "syscalls"
    env = ["FLAG=flag{override}"]
    user = "ctf:ctf"
    argv = '["/bin/sh","-c","/start.sh"]'
    shell_mode = True
    hostname = "override-host"
    gdb_multi_port = 9000
    gdb_attach_port = None
    enable_gdb_attach = False
    disable_gdb_attach = False
    qemu_gdb_port = 9001
    keep_shell = None
    allow_root_fallback = True
    verbose = 0
    dry_run = False


def test_example_config_and_cli_override_merge() -> None:
    example = Path("examples/contrace.yml")
    file_config = load_file_config(example)
    overrides = cli_overrides_from_args(Args())
    resolved = resolve_config(file_config, overrides)

    assert resolved.guest_arch == "x86_64"
    assert resolved.hostname == "override-host"
    assert resolved.trace_preset == "syscalls"
    assert resolved.runtime_user == "ctf:ctf"
    assert resolved.argv == ["/bin/sh", "-c", "/start.sh"]
    assert resolved.env["FLAG"] == "flag{override}"
    assert resolved.service_ports == [31337]
    assert {item.guest: item.host for item in resolved.forwards}[31337] == 4444
    assert resolved.gdb_multi_port == 9000
    assert resolved.gdb_attach_port == 1235
    assert resolved.qemu_gdb_port == 9001
    assert resolved.allow_root_fallback is True
