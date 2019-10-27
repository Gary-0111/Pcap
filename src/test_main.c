#include "pcap.h"
#include "xtest.h"
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include "filter.h"

const char *pcap_file = "../atp.pcap";

int udp_packet_dump(mac_frame frame, void *udata)
{
	static int cnt = 0;
	printf("====================== Packet #%d =====================\n", ++cnt);
	mac_dump(frame);
	ip_pkt pkt = get_ip_pkt(frame);
	ip_dump(pkt);
	udp_dump(get_udp_pkt(pkt));

	return 0;
}

int count_packet(mac_frame frame, void *udata)
{
	(*(int *)udata)++;
	return 0;
}

//  完成使用场景的测试
/*
TEST(PCAP, READ)
{
	pcap_fp pcap = pcap_open("afdsfsf");
	EXPECT_EQ(NULL, pcap);

	pcap = pcap_open(pcap_file);
	EXPECT_NE(NULL, pcap);
	
	mac_frame first_frame = pcap_next_frame(pcap);
	EXPECT_NE(NULL, first_frame);
	
	mac_frame last_frame = first_frame;
	while (TRUE)
	{
		mac_frame tmp_frame = pcap_next_frame(pcap);
		if (tmp_frame == NULL) {
			break;
		}
		last_frame = tmp_frame;
	}

	pcap_close(pcap);
}
*/
TEST(FILTER, PROTOCOL)
{
	int cnt = 0;
	filter ft_ip = filter_protocol(NETWORK_LAYER, IPPROTO);
	EXPECT_NE(NULL, ft_ip);
	pcap_for_each(pcap_file, ft_ip, count_packet, &cnt);
	EXPECT_EQ(457, cnt);
	filter_free(ft_ip);

	cnt = 0;
	filter ft_ipv6 = filter_protocol(NETWORK_LAYER, IPPROTOV6);
	EXPECT_NE(NULL, ft_ipv6);
	pcap_for_each(pcap_file, ft_ipv6, count_packet, &cnt);
	EXPECT_EQ(19, cnt);
	filter_free(ft_ipv6);

	cnt = 0;
	filter ft_tcp = filter_protocol(TRANSPORT_LAYER, IPPROTO_TCP);
	EXPECT_NE(NULL, ft_tcp);
	pcap_for_each(pcap_file, ft_tcp, count_packet, &cnt);
	EXPECT_EQ(89, cnt);
	filter_free(ft_tcp);

	cnt = 0;
	filter ft_udp = filter_protocol(TRANSPORT_LAYER, IPPROTO_UDP);
	EXPECT_NE(NULL, ft_udp);
	pcap_for_each(pcap_file, ft_udp, count_packet, &cnt);
	EXPECT_EQ(354, cnt);
	filter_free(ft_udp);
}

TEST(FILTER, IP)
{
	int cnt = 0;
	filter ft_src_ip = filter_src_ip("200.200.66.19");
	EXPECT_NE(NULL, ft_src_ip);
	pcap_for_each(pcap_file, ft_src_ip, count_packet, &cnt);
	EXPECT_EQ(6, cnt);
	filter_free(ft_src_ip);

	cnt = 0;
	filter ft_dst_ip = filter_dst_ip("224.0.0.252");
	EXPECT_NE(NULL, ft_dst_ip);
	pcap_for_each(pcap_file, ft_dst_ip, count_packet, &cnt);
	EXPECT_EQ(14, cnt);
	filter_free(ft_dst_ip);
}

/*
TEST(FILTER, PORT)
{
	int cnt = 0;
	filter ft_src_port = filter_src_port(34570);
	EXPECT_NE(NULL, ft_src_port);
	pcap_for_each(pcap_file, ft_src_port, count_packet, &cnt);
	EXPECT_EQ(60, cnt);
	filter_free(ft_src_port);

	cnt = 0;
	filter ft_dst_port = filter_dst_port(443);
	EXPECT_NE(NULL, ft_dst_port);
	pcap_for_each(pcap_file, ft_dst_port, count_packet, &cnt);
	EXPECT_EQ(40, cnt);
	filter_free(ft_dst_port);
}

TEST(FILTER, ROUND)
{
	__u16 port = 34570;
    filter ft_src_port = filter_src_port(port);
    filter ft_dst_port = filter_dst_port(port);
    filter ft_proto = filter_protocol(TRANSPORT_LAYER, IPPROTO_UDP);

    filter ft_port = filter_or(ft_src_port, ft_dst_port);
	filter not_ft = filter_not(ft_port);
	filter ft = filter_and(ft_proto, not_ft);
	filter_dump(ft);

	int cnt = 0;
    pcap_for_each(pcap_file, ft, count_packet, &cnt);
	pcap_for_each(pcap_file, ft, udp_packet_dump, NULL);
	EXPECT_EQ(294, cnt);
	filter_free(ft);
}
*/

int main(int argc, char **argv)
{
	return xtest_start_test(argc, argv);
}

