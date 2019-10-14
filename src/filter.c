

struct IP_HEAD
{
    unsigned char verhlen;  // :4位version, 4位len (<<2) 45H
    unsigned char tos;      // 服务,优先级，正常设为0
    unsigned short len;     // 长度，以字节表示数据报总长度，包括IP 报文头
    unsigned short ident;   // 标识
    unsigned short frags;   // 分段
    unsigned char ttl;      // 生存时间,典型值：100 秒
    unsigned char procotol; // 协议 ,数据域所用协议，比如：1-ICMP 6-TCP，0x11-UDP
    unsigned short crc;     // 校验和,仅仅是IP 头的简单校验和
    unsigned int srcip;     // 4 字节源IP 地址
    unsigned int dstip;     // 4 字节目的IP 地址
};

struct TCP_HEAD
{
    unsigned short srcport; //源端口
    unsigned short dstport; //目标端口
    unsigned int seq;
    unsigned int ack;
    unsigned char hlen;     //头部长度
    char notcare[0];        //不关心
};

struct UDP_HEAD
{
    unsigned short srcport;
    unsigned short dstport;
    unsigned short len;
    unsigned short crc;
};

