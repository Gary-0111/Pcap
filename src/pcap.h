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

typedef int (*pcap_callback)(mac_frame, void *udata);              // 钩子原型



/******************* API ********************/
/**
 * @brief 打开pcap文件
 * @param fname pcap文件路径
 * @return 成功则返回pcap指针；失败返回NULL
 */
pcap_fp pcap_open(const char *fname); 

/**
 * @brief 关闭pcap文件
 * @param pcap pcap指针
 */
void    pcap_close(pcap_fp pcap);

/**
 * @brief 读取下一个以太网帧
 * @param pcap pcap指针
 * @return 成功则返回下一个mac帧；失败返回NULL
 */
mac_frame pcap_next_frame(pcap_fp pcap);

/**
 * @brief 读取pcap文件遍历每一帧，并对每一帧调用hook处理
 * @param fname pcap文件路径
 * @param hook  回调函数
 * @param udata 回调函数的参数
 * @return 成功返回0；失败返回-1
 */
int pcap_parse_all(const char *fname, pcap_callback hook, void *udata);



#ifdef __cplusplus
}
#endif

#endif //PCAP_H_
