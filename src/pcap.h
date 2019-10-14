#ifndef PCAP_H_
#define PCAP_H_

#ifdef __cplusplus
extern "C" {
#endif

#define MAC_LEN 6

typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

// 以太网帧头
struct MAC_HEAD {
    __u8 dst_mac[MAC_LEN];
    __u8 src_mac[MAC_LEN];
    __u16 protocol;
};

typedef struct pcap_st *pcap_fp;
typedef struct MAC_HEAD *mac_frame;

typedef int (*hook_func)(mac_frame);              // 钩子原型



/******************* API ********************/
pcap_fp pcap_open(const char *fname);               // 打开pcap文件
void    pcap_close(pcap_fp pcap);                   // 关闭pcap文件

mac_frame pcap_next_frame(pcap_fp pcap);              // 读取下一个pcap帧

int pcap_loads(const char *fname, hook_func hook);  // 读取pcap文件遍历每一帧，并对每一帧调用hook处理



#ifdef __cplusplus
}
#endif

#endif //PCAP_H_
