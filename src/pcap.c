#include "pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define MAX_MAC_FRAME_LEN 1600

/**
 *  PCAP文件的文件头
 */
typedef struct _pcap_file_header {
    __u32 magic;            //主标识:a1b2c3d4
    __u16 version_major;    //主版本号
    __u16 version_minor;    //次版本号
    __u32 thiszone;         //区域时间0
    __u32 sigfigs;          //时间戳0
    __u32 snaplen;          //数据包最大长度
    __u32 linktype;         //链路层类型，取值：DLT_*
} pcap_file_header;

/*
 * These are the types that are the same on all platforms, and that
 * have been defined by <net/bpf.h> for ages.
 */
#define DLT_NULL    0   /* BSD loopback encapsulation */
#define DLT_EN10MB  1   /* Ethernet (10Mb) */
#define DLT_EN3MB   2   /* Experimental Ethernet (3Mb) */
#define DLT_AX25    3   /* Amateur Radio AX.25 */
#define DLT_PRONET  4   /* Proteon ProNET Token Ring */
#define DLT_CHAOS   5   /* Chaos */
#define DLT_IEEE802 6   /* IEEE 802 Networks */
#define DLT_ARCNET  7   /* ARCNET, with BSD-style header */
#define DLT_SLIP    8   /* Serial Line IP */
#define DLT_PPP     9   /* Point-to-point Protocol */
#define DLT_FDDI    10  /* FDDI */


#ifdef __OpenBSD__
#define DLT_RAW     14  /* raw IP */
#else
#define DLT_RAW     12  /* raw IP */
#endif



/**
 *  PCAP文件中数据包所使用的时间戳
 */
typedef struct _pcap_time_stamp {
    __u32 tv_sec;
    __u32 tv_usec;
} pcap_time_stamp;

/**
 *  PCAP文件中数据包的头部
 */
typedef struct _pcap_pkthdr {
    pcap_time_stamp ts;
    __u32 caplen;
    __u32 len;
} pcap_pkthdr;



typedef struct _pcap_st {
    pcap_file_header header;
    FILE *fp;
} pcap_st;


/**
 * @brief 打开pcap文件
 * @param fname pcap文件路径
 * @return 成功则返回pcap指针；失败返回NULL
 */
pcap_fp pcap_open(const char *fname) 
{
    assert(fname);
    pcap_st *pcap = NULL;
    pcap = (pcap_st *)malloc(sizeof(pcap_st));
    int ret = 0;
    
    if (pcap == NULL)
        return NULL;

    pcap->fp = fopen(fname, "rb");
    if (pcap->fp == NULL) {
        pcap_close((pcap_fp)pcap);
        return NULL;
    }
    
    ret = fread(&(pcap->header), sizeof(pcap_file_header), 1, pcap->fp);
    if (ret != 1) {
        pcap_close((pcap_fp)pcap);
        return NULL;
    }
    // 只支持以太网的解析
    if (((pcap_st *)pcap)->header.linktype != DLT_EN10MB) {
        pcap_close((pcap_fp)pcap);
        return NULL;
    }
    return (pcap_fp)pcap;
}


/**
 * @brief 关闭pcap文件
 * @param pcap pcap指针
 */
void pcap_close(pcap_fp pcap) 
{
    if (pcap) {
        if (((pcap_st *)pcap)->fp) {
            fclose(((pcap_st *)pcap)->fp);
        }
        free(pcap);
    }
}


/**
 * @brief 读取下一个以太网帧
 * @param pcap pcap指针
 * @return 成功则返回下一个mac帧；失败返回NULL
 */
mac_frame pcap_next_frame(pcap_fp pcap)
{
    assert(pcap);
    assert(((pcap_st *)pcap)->fp);

    static __u8 data[MAX_MAC_FRAME_LEN];
    
    int ret = 0;
    pcap_pkthdr pkthdr;
    FILE *fp = ((pcap_st *)pcap)->fp;

    ret = fread(&(pkthdr), sizeof(pcap_pkthdr), 1, fp);
    if (ret != 1) {
        return NULL;
    }

    //printf("pkthdr.caplen = %u\n", pkthdr.caplen);
    
    ret = fread(data, 1, pkthdr.caplen, fp);
    if (ret != pkthdr.caplen) {
        return NULL;
    }

    return (mac_frame)data;
}

/**
 * @brief 读取pcap文件遍历每一帧，并对每一帧调用hook处理
 * @param fname pcap文件路径
 * @param hook  回调函数
 * @param udata 回调函数的参数
 * @return 成功返回0；失败返回-1
 */
int pcap_parse_all(const char *fname, pcap_callback hook, void *udata)
{
    assert(fname);
    assert(hook);

    pcap_fp pcap = pcap_open(fname);
    if (pcap == NULL) {
        return -1;
    }
    
    mac_frame frame = pcap_next_frame(pcap);
    while (frame) {
        hook(frame, udata);
        frame = pcap_next_frame(pcap);
    }
    pcap_close(pcap);
    return 0;
}
