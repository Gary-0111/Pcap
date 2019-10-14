#include "pcap.h"
#include "xtest.h"
#include <stdio.h>
#include <assert.h>
#include <errno.h>

const char *pcap_file = "atp.pcap";

int hook(mac_frame frame)
{
	if (frame->protocol)
	return 0;
}

//  完成使用场景的测试

TEST(test, scene)
{
	pcap_fp pcap = pcap_open(pcap_file);

	EXPECT_NE(NULL, pcap);
	EXPECT_NE(NULL, pcap_next_frame(pcap));
	EXPECT_NE(NULL, pcap_next_frame(pcap));
	pcap_close(pcap);

}

TEST(test, round)
{
	pcap_loads(pcap_file, hook);
}

int main(int argc, char **argv)
{
	return xtest_start_test(argc, argv);
}

