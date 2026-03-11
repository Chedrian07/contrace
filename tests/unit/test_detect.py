from contrace.detect import classify_manager, infer_ports_from_argv, parse_inetd_conf, parse_xinetd_configs


def test_classify_manager_and_infer_ports() -> None:
    argv = ["socat", "TCP-LISTEN:31337,reuseaddr,fork", "EXEC:/home/ctf/chall"]
    assert classify_manager(argv) == "socat"
    assert infer_ports_from_argv(argv) == [31337]


def test_parse_xinetd_and_inetd_configs() -> None:
    xinetd_ports = parse_xinetd_configs(
        [
            ("/etc/xinetd.d/chall", "service chall\n{\n  port = 4444\n}\n"),
        ]
    )
    inetd_ports = parse_inetd_conf("1337 stream tcp nowait root /usr/sbin/tcpd /bin/chall\n")

    assert xinetd_ports == [4444]
    assert inetd_ports == [1337]
