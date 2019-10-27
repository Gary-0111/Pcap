#ifndef FILTER_H_
#define FILTER_H_

#include "pcap.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IPPROTO     0x800
#define IPPROTOV6   0x86dd

#define TRUE  1
#define FALSE 0

typedef int BOOL;


typedef struct IP_HEAD
{
    __u8 verhlen;  // :4位version, 4位len (<<2) 45H
    __u8 tos;      // 服务,优先级，正常设为0
    __u16 len;     // 长度，以字节表示数据报总长度，包括IP 报文头
    __u16 ident;   // 标识
    __u16 frags;   // 分段
    __u8 ttl;      // 生存时间,典型值：100 秒
    __u8 procotol; // 协议 ,数据域所用协议，比如：1-ICMP 6-TCP，0x11-UDP
    __u16 crc;     // 校验和,仅仅是IP 头的简单校验和
    __u32 srcip;   // 4 字节源IP 地址
    __u32 dstip;   // 4 字节目的IP 地址
} *ip_pkt;

typedef struct TCP_HEAD
{
    __u16 srcport; //源端口
    __u16 dstport; //目标端口
    __u32 seq;
    __u32 ack;
    __u8 hlen;     //头部长度
    char notcare[0];        //不关心
} *tcp_pkt;

typedef struct UDP_HEAD
{
    __u16 srcport;
    __u16 dstport;
    __u16 len;
    __u16 crc;
} *udp_pkt;


typedef enum {
    LOGICAL_NONE,
    LOGICAL_AND,              // 逻辑操作符
    LOGICAL_OR,
    LOGICAL_NOT
} logic_oper_type;

enum {
    NETWORK_LAYER,
    TRANSPORT_LAYER
};


typedef enum {
    EXPRESSION_UNKNOW,
    EXPRESSION_NETWORK_LAYER_PROTOCOL,         // 过滤协议类型
    EXPRESSION_TRANSPORT_LAYER_PROTOCOL,
    EXPRESSION_SIP,
    EXPRESSION_DIP,
    EXPRESSION_SPORT,
    EXPRESSION_DPORT
} expression_type;


typedef int (*filter_callback)(mac_frame, void *udata);              // 钩子原型

typedef struct filter_st *filter;

/**
 * @brief 从mac帧获取IP包
 * @param frame mac帧
 * @return IP包
 */
ip_pkt get_ip_pkt(mac_frame);

/**
 * @brief 计算IP包头长度（字节）
 * @param pkt  IP包
 * @return 长度
 */
__u8 get_ip_header_len(ip_pkt pkt);

/**
 * @brief 从IP包中获取TCP报文
 * @param pkt  IP包
 * @return TCP报文
 */
tcp_pkt get_tcp_pkt(ip_pkt pkt);

/**
 * @brief 从IP包中获取UDP包
 * @param pkt  IP包
 * @return UDP包
 */
udp_pkt get_udp_pkt(ip_pkt pkt);



/** 
 * @brief 打印MAC帧头
 * @param frame mac帧
 */
void mac_dump(mac_frame frame);

/** 
 * @brief 打印IP包头
 * @param pkt  IP包
 */
void ip_dump(ip_pkt pkt);

/** 
 * @brief 打印TCP包头
 * @param pkt  TCP包
 */
void tcp_dump(tcp_pkt pkt);

/** 
 * @brief 打印UDP包头
 * @param pkt  UDP包
 */
void udp_dump(udp_pkt pkt);

/** 
 * @brief 打印UDP包内容
 * @param pkt  UDP包
 */
void print_udp_data(udp_pkt);


/** 
 * @brief 轮询fname文件的包，满足过滤器ft条件时，则调用用户回调函数fcb
 * @param fname pcap文件路径  
 * @param ft    过滤器
 * @param fcb   用户回调函数
 * @param udata 回调函数的参数
 * 
 */
int pcap_for_each(const char *fname, filter ft, filter_callback fcb, void *data);       

/**
 * @brief 判断mac帧是否满足过滤器条件
 * @param frame MAC帧
 * @param ft    过滤器
 * @return TRUE 符合条件； FALSE 不符合条件
 */
BOOL match(mac_frame frame, filter ft);

/**
 * @brief 新建一个协议过滤器
 * @param layer    协议所在层级（NETWORK_LAYER， TRANSPORT_LAYER）
 * @param protocol 协议
 * @return 协议过滤器
 */
filter filter_protocol(int layer, int protocol);

/**
 * @brief 新建一个源IP过滤器
 * @param ip   源IP字符串
 * @return 源IP过滤器
 */
filter filter_src_ip(const char *ip);

/**
 * @brief 新建一个目的IP过滤器
 * @param ip   目的IP字符串
 * @return 目的IP过滤器
 */
filter filter_dst_ip(const char *ip);

/**
 * @brief 新建一个源端口过滤器
 * @param port   源端口字符串
 * @return 源端口过滤器
 */
filter filter_src_port(__u16 port);

/**
 * @brief 新建一个目的端口过滤器
 * @param port   目的端口字符串
 * @return 目的端口过滤器
 */
filter filter_dst_port(__u16 port);

/**
 * @brief 将两个过滤器进行 与 操作
 * @param loperand  过滤器1
 * @param roperand  过滤器2
 * @return  与 操作后的过滤器
 */
filter filter_and(filter loperand, filter roperand); 

/**
 * @brief 将两个过滤器进行 或 操作
 * @param loperand  过滤器1
 * @param roperand  过滤器2
 * @return  或 操作后的过滤器
 */
filter filter_or(filter loperand, filter roperand);

/**
 * @brief 将两个过滤器进行 非 操作
 * @param operand  过滤器1
 * @param roperand  过滤器2
 * @return  非 操作后的过滤器
 */
filter filter_not(filter operand);

/**
 * @brief 释放过滤器内存
 * @param ft  过滤器
 */
void filter_free(filter);   

/**
 * @brief 打印过滤器的过滤条件
 * @param ft  过滤器
 */
void filter_dump(filter ft);




#ifdef __cplusplus
}
#endif

#endif //FILTER_H_
