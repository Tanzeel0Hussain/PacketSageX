from packetsagex.intelligence import NetworkIntelligence
from packetsagex.models import PacketRecord


def test_endpoint_dns_tls_quic_analytics():
    intel=NetworkIntelligence()
    intel.add(PacketRecord(1,1.0,120,'192.168.1.10','8.8.8.8','DNS',53000,53,dns_query='example.com'))
    intel.add(PacketRecord(2,1.1,180,'8.8.8.8','192.168.1.10','DNS',53,53000,dns_query='example.com',dns_is_response=True,dns_rcode='3'))
    intel.add(PacketRecord(3,1.2,800,'192.168.1.10','1.1.1.1','TLS',50000,443,server_name='github.com',tls_version='0x0303'))
    intel.add(PacketRecord(4,1.3,900,'192.168.1.10','1.0.0.1','QUIC',50001,443,quic_version='0x00000001'))
    inventory=intel.endpoint_inventory(); assert inventory[0]['endpoint']=='192.168.1.10'; assert inventory[0]['scope']=='private/local'; assert inventory[0]['peer_count']==3
    dns=intel.dns_analytics(); assert dns['query_packets']==1; assert dns['response_packets']==1; assert dns['unique_queries']==1; assert dns['nxdomain_count']==1
    encrypted=intel.tls_quic_intelligence(); assert encrypted['tls_packets']==1; assert encrypted['quic_packets']==1; assert encrypted['top_server_names'][0]['server_name']=='github.com'
