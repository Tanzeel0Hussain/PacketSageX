from packetsagex.nmap_import import parse_nmap_xml


def test_parse_nmap_sample(tmp_path):
    sample = tmp_path / "scan.xml"
    sample.write_text("""<?xml version='1.0'?><nmaprun scanner='nmap'><host><status state='up'/><address addr='192.168.1.10' addrtype='ipv4'/><ports><port protocol='tcp' portid='22'><state state='open'/><service name='ssh' product='OpenSSH'/></port></ports></host></nmaprun>""", encoding="utf-8")
    report = parse_nmap_xml(sample)
    assert report["host_count"] == 1
    assert report["open_port_count"] == 1
    assert report["hosts"][0]["ports"][0]["service"] == "ssh"
