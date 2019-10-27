#include "pcap.h"
#include <stdio.h>
#include "filter.h"

#include <assert.h>
#include <arpa/inet.h>

//---------------------------------------------------------------------------
//  方案1
//---------------------------------------------------------------------------


const char *pcap_file = "../atp.pcap";

int udp_packet_dump(mac_frame frame, void *udata)
{
	static int cnt = 0;
	/*printf("====================== Packet #%d =====================\n", ++cnt);
	mac_dump(frame);
	ip_pkt pkt = get_ip_pkt(frame);
	ip_dump(pkt);
	udp_dump(get_udp_pkt(pkt));
*/
	return 0;
}


int main(int argc, char *argv[])
{
    __u16 port = 34570;
    filter ft_src_port = filter_src_port(port);
    filter ft_dst_port = filter_dst_port(port);
    filter ft_proto = filter_protocol(TRANSPORT_LAYER, IPPROTO_UDP);

    filter ft_port = filter_or(ft_src_port, ft_dst_port);
	filter not_ft = filter_not(ft_port);
	filter ft = filter_and(ft_proto, not_ft);

    pcap_for_each(pcap_file, ft, udp_packet_dump, NULL);

	filter_free(ft);

    return 0;
}
