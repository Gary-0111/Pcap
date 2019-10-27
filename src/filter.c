#include "filter.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>




// 过滤条件
typedef struct expression_st {
    expression_type expr_type;            // 过滤类型
    union {                               //
        __u32 ip;                         // 过滤IP
        __u16 port;                       // 过滤端口
        __u16 protocol;                   // 过滤协议
    };
} expression;


typedef struct filter_op {
    filter_callback fcb;                    // 用户的回调函数
} filter_op;

// 过滤器
struct filter_st {
    filter_op *operation;               
    void *udata;                        // 回调函数的udata参数
    union {
        logic_oper_type op_type;        // lchild或rchild不为空时有效（非叶节点）
        expression expr;                // lchild和rchild为空时有效（叶子）
    };
    struct filter_st *lchild, *rchild;  
};


/** 
 * @brief 打印MAC地址
 * @param mac   mac地址
 */
void print_mac_addr(__u8 *mac)
{
    assert(mac);

    for (int i = 0; i < MAC_LEN; ++i)
	{
		printf("%02x%s", mac[i], (i == MAC_LEN - 1) ? "": ":");
	}
}

/** 
 * @brief 打印MAC帧头
 * @param frame mac帧
 */
void mac_dump(mac_frame frame)
{
    assert(frame);

    printf("--------------- MAC ----------------\n");
    printf("dst_mac:  ");
	print_mac_addr(frame->dst_mac);
	printf("\nsrc_mac:  ");
	print_mac_addr(frame->src_mac);
	printf("\nprotocol: 0x%04x\n", ntohs(frame->protocol));
}

/** 
 * @brief 打印IP包头
 * @param pkt  IP包
 */
void ip_dump(ip_pkt pkt)
{
    assert(pkt);

    printf("--------------- IP -----------------\n");
    printf("verhlen:  0x%02x\n", pkt->verhlen);
    printf("tos:      0x%02x\n", pkt->tos);
    printf("len:      %d\n", ntohs(pkt->len));
    printf("ident:    0x%04x\n", ntohs(pkt->ident));
    printf("frags:    0x%04x\n", ntohs(pkt->frags));
    printf("ttl:      %d\n", pkt->ttl);
    printf("protocol: 0x%02x\n", pkt->procotol);
    printf("crc:      0x%04x\n", ntohs(pkt->crc));
    struct in_addr srcaddr, dstaddr;
    srcaddr.s_addr = pkt->srcip;
    dstaddr.s_addr = pkt->dstip;
    printf("src_ip:   %s\n", inet_ntoa(srcaddr));
    printf("dst_ip:   %s\n", inet_ntoa(dstaddr));
}

/** 
 * @brief 打印TCP包头
 * @param pkt  TCP包
 */
void tcp_dump(tcp_pkt pkt)
{
    assert(pkt);
}

/** 
 * @brief 打印UDP包头
 * @param pkt  UDP包
 */
void udp_dump(udp_pkt pkt)
{
    assert(pkt);

    printf("--------------- UDP ----------------\n");
    printf("srcport:  %d\n", ntohs(pkt->srcport));
    printf("dstport:  %d\n", ntohs(pkt->dstport));
    printf("len:      %d\n", ntohs(pkt->len));
    printf("crc:      0x%04x\n", ntohs(pkt->crc));
    printf("data: \n");
    print_udp_data(pkt);
}

/** 
 * @brief 打印UDP包内容
 * @param pkt  UDP包
 */
void print_udp_data(udp_pkt pkt)
{
    assert(pkt);

    int len = ntohs(pkt->len) - sizeof(struct UDP_HEAD);
    int column = 16;
    __u8 *udp_data = (__u8*)pkt + sizeof(struct UDP_HEAD);
    for(int i = 0; i < len; ++i)
    {
        printf("%02x%c", udp_data[i], (i+1)%column == 0 ? '\n' : ' ');
    }
    printf("\n");
}


/**
 * @brief 符合ft过滤器条件，则调用用户的回调函数
 * @param frame mac帧
 * @param ft    过滤器
 * 
 */
int filter_pkt(mac_frame frame, void *ft)
{
    assert(frame);
    assert(ft);

    if(match(frame, ft))
    {
        ((filter)ft)->operation->fcb(frame, ((filter)ft)->udata);
        //ip_dump(get_ip_pkt(frame));
    } 
    return 0;
}

/** 
 * @brief 轮询fname文件的包，满足过滤器ft条件时，则调用用户回调函数fcb
 * @param fname pcap文件路径  
 * @param ft    过滤器
 * @param fcb   用户回调函数
 * @param udata 回调函数的参数
 * 
 */
int pcap_for_each(const char *fname, filter ft, filter_callback fcb, void *udata)      
{
    assert(fname);
    assert(ft);
    assert(fcb);

    ft->operation = malloc(sizeof(filter_op));
    ft->operation->fcb = fcb;
    ft->udata = udata;
    pcap_parse_all(fname, &filter_pkt, (void*)ft);
    return 0;
}


/**
 * @brief 从mac帧获取IP包
 * @param frame mac帧
 * @return IP包
 */
ip_pkt get_ip_pkt(mac_frame frame)
{
    assert(frame);
    assert(ntohs(frame->protocol) == IPPROTO);
    
    return (ip_pkt)(((void*)frame) + sizeof(struct MAC_HEAD));
}

/**
 * @brief 计算IP包头长度（字节）
 * @param pkt  IP包
 * @return 长度
 */
__u8 get_ip_header_len(ip_pkt pkt)
{
    assert(pkt);

    return (pkt->verhlen & 0xf) << 2;
}

/**
 * @brief 从IP包中获取TCP报文
 * @param pkt  IP包
 * @return TCP报文
 */
tcp_pkt get_tcp_pkt(ip_pkt pkt)
{
    assert(pkt);

    return (tcp_pkt)((void*)pkt + get_ip_header_len(pkt));
}

/**
 * @brief 从IP包中获取UDP包
 * @param pkt  IP包
 * @return UDP包
 */
udp_pkt get_udp_pkt(ip_pkt pkt)
{
    assert(pkt);

    return (udp_pkt)((void*)pkt + get_ip_header_len(pkt));
}

/**
 * @brief 判断第三层的协议是否符合过滤条件
 * @param frame  MAC帧
 * @param expr   过滤条件
 * @return TRUE 符合条件； FALSE 不符合条件
 */
BOOL match_network_layer_protocol(mac_frame frame, expression expr)
{
    assert(frame);
    
    return ntohs(frame->protocol) == expr.protocol;
}

/**
 * @brief 判断第四层的协议是否符合过滤条件
 * @param frame  MAC帧
 * @param expr   过滤条件
 * @return TRUE 符合条件； FALSE 不符合条件
 */
BOOL match_transport_layer_protocol(mac_frame frame, expression expr)
{
    assert(frame);

    if (ntohs(frame->protocol) != IPPROTO)
        return FALSE;

    //printf("ip.protocol: %x\n", ((ip_pkt)get_ip_pkt(frame))->procotol);
    return get_ip_pkt(frame)->procotol == expr.protocol;
}

/**
 * @brief 判断源IP是否符合过滤条件
 * @param frame  MAC帧
 * @param expr   过滤条件
 * @return TRUE 符合条件； FALSE 不符合条件
 */
BOOL match_src_ip(mac_frame frame, expression expr)
{
    assert(frame);
    
    if (ntohs(frame->protocol) != IPPROTO)
        return FALSE;

    return get_ip_pkt(frame)->srcip == expr.ip;
}

/**
 * @brief 判断目的IP是否符合过滤条件
 * @param frame  MAC帧
 * @param expr   过滤条件
 * @return TRUE 符合条件； FALSE 不符合条件
 */
BOOL match_dst_ip(mac_frame frame, expression expr)
{
    assert(frame);
    
    if (ntohs(frame->protocol) != IPPROTO)
        return FALSE;

    return get_ip_pkt(frame)->dstip == expr.ip;
}

/**
 * @brief 判断源端口是否符合过滤条件
 * @param frame  MAC帧
 * @param expr   过滤条件
 * @return TRUE 符合条件； FALSE 不符合条件
 */
BOOL match_src_port(mac_frame frame, expression expr)
{
    assert(frame);
    
    if (ntohs(frame->protocol) != IPPROTO)
        return FALSE;

    ip_pkt pkt = get_ip_pkt(frame);
    if (pkt->procotol == IPPROTO_TCP)
    {
        return ntohs(get_tcp_pkt(pkt)->srcport) == expr.port;
    }
    else if (pkt->procotol == IPPROTO_UDP)
    {
        return ntohs(get_udp_pkt(pkt)->srcport) == expr.port;
    }
    return FALSE;
}

/**
 * @brief 判断目的端口是否符合过滤条件
 * @param frame  MAC帧
 * @param expr   过滤条件
 * @return TRUE 符合条件； FALSE 不符合条件
 */
BOOL match_dst_port(mac_frame frame, expression expr)
{
    assert(frame);
    
    if (ntohs(frame->protocol) != IPPROTO)
        return FALSE;

    ip_pkt pkt = get_ip_pkt(frame);
    if (pkt->procotol == IPPROTO_TCP)
    {
        return ntohs(get_tcp_pkt(pkt)->dstport) == expr.port;
    }
    else if (pkt->procotol == IPPROTO_UDP)
    {
        return ntohs(get_udp_pkt(pkt)->dstport) == expr.port;
    }
    return FALSE;
}

/**
 * @brief 判断mac帧是否符合不同类型的过滤条件
 * @param frame  MAC帧
 * @param expr   过滤条件
 * @return TRUE 符合条件； FALSE 不符合条件
 */
BOOL match_expression(mac_frame frame, expression expr)
{
    assert(frame);

    switch (expr.expr_type)
    {
        case EXPRESSION_NETWORK_LAYER_PROTOCOL:
            return match_network_layer_protocol(frame, expr);
        case EXPRESSION_TRANSPORT_LAYER_PROTOCOL:
            return match_transport_layer_protocol(frame, expr);
        case EXPRESSION_SIP:
            return match_src_ip(frame, expr);
        case EXPRESSION_DIP:
            return match_dst_ip(frame, expr);
        case EXPRESSION_SPORT:
            return match_src_port(frame, expr);
        case EXPRESSION_DPORT:
            return match_dst_port(frame, expr);
        default: break;
    }
    return FALSE;
}

/**
 * @brief 判断mac帧是否满足过滤器条件
 * @param frame MAC帧
 * @param ft    过滤器
 * @return TRUE 符合条件； FALSE 不符合条件
 */
BOOL match(mac_frame frame, filter ft)        
{
    assert(frame);
    assert(ft);

    if (ft->lchild == NULL && ft->rchild == NULL)
        return match_expression(frame, ft->expr);

    switch (ft->op_type)
    {
        case LOGICAL_AND:
            return match(frame, ft->lchild) && match(frame, ft->rchild);
        case LOGICAL_OR:
            return match(frame, ft->lchild) || match(frame, ft->rchild);
        case LOGICAL_NOT:
            return !match(frame, ft->lchild);
        default: 
            return FALSE;
    }
}

/**
 * @brief 新建一个协议过滤器
 * @param layer    协议所在层级（NETWORK_LAYER， TRANSPORT_LAYER）
 * @param protocol 协议
 * @return 协议过滤器
 */
filter filter_protocol(int layer, int protocol)
{
    filter ft = calloc(1, sizeof(struct filter_st));
    if (ft == NULL)
    {
        return NULL;
    }
    if (layer == NETWORK_LAYER)
        ft->expr.expr_type = EXPRESSION_NETWORK_LAYER_PROTOCOL;
    else if (layer == TRANSPORT_LAYER)
        ft->expr.expr_type = EXPRESSION_TRANSPORT_LAYER_PROTOCOL;
    else
        ft->expr.expr_type = EXPRESSION_UNKNOW;
    
    ft->expr.protocol = protocol;

    //filter_dump(ft);
    return ft;
}

/**
 * @brief 新建一个源IP过滤器
 * @param ip   源IP字符串
 * @return 源IP过滤器
 */
filter filter_src_ip(const char *ip)
{
    assert(ip);

    filter ft = calloc(1, sizeof(struct filter_st));
    if (ft == NULL)
    {
        return NULL;
    }

    ft->expr.expr_type = EXPRESSION_SIP;
    ft->expr.ip = inet_addr(ip);
    //printf("filter src ip: %x\n", ft->expr.ip);
    return ft;
}

/**
 * @brief 新建一个目的IP过滤器
 * @param ip   目的IP字符串
 * @return 目的IP过滤器
 */
filter filter_dst_ip(const char *ip)
{
    assert(ip);
    
    filter ft = calloc(1, sizeof(struct filter_st));
    if (ft == NULL)
    {
        return NULL;
    }

    ft->expr.expr_type = EXPRESSION_DIP;
    ft->expr.ip = inet_addr(ip);
    //printf("filter dst ip: %x\n", ft->expr.ip);
    return ft;
}

/**
 * @brief 新建一个源端口过滤器
 * @param port   源端口字符串
 * @return 源端口过滤器
 */
filter filter_src_port(__u16 port)
{
    filter ft = calloc(1, sizeof(struct filter_st));
    if (ft == NULL)
    {
        return NULL;
    }

    ft->expr.expr_type = EXPRESSION_SPORT;
    ft->expr.port = port;
    //printf("filter src port: %x\n", ft->expr.port);
    return ft;
}

/**
 * @brief 新建一个目的端口过滤器
 * @param port   目的端口字符串
 * @return 目的端口过滤器
 */
filter filter_dst_port(__u16 port)
{
    filter ft = calloc(1, sizeof(struct filter_st));
    if (ft == NULL)
    {
        return NULL;
    }

    ft->expr.expr_type = EXPRESSION_DPORT;
    ft->expr.port = port;
    //printf("filter dst port: %x\n", ft->expr.port);
    return ft;
}

/**
 * @brief 将两个过滤器进行 与 操作
 * @param loperand  过滤器1
 * @param roperand  过滤器2
 * @return  与 操作后的过滤器
 */
filter filter_and(filter loperand, filter roperand) 
{
    assert(loperand);
    assert(roperand);

    filter ft = calloc(1, sizeof(struct filter_st));
    if (ft == NULL)
    {
        return NULL;
    }

    ft->op_type = LOGICAL_AND;
    ft->lchild = loperand;
    ft->rchild = roperand;

    return ft;
}

/**
 * @brief 将两个过滤器进行 或 操作
 * @param loperand  过滤器1
 * @param roperand  过滤器2
 * @return  或 操作后的过滤器
 */
filter filter_or(filter loperand, filter roperand)
{
    assert(loperand);
    assert(roperand);
    
    filter ft = calloc(1, sizeof(struct filter_st));
    if (ft == NULL)
    {
        return NULL;
    }

    ft->op_type = LOGICAL_OR;
    ft->lchild = loperand;
    ft->rchild = roperand;

    return ft;
}

/**
 * @brief 将两个过滤器进行 非 操作
 * @param operand  过滤器1
 * @param roperand  过滤器2
 * @return  非 操作后的过滤器
 */
filter filter_not(filter operand)
{
    assert(operand);
    
    filter ft = calloc(1, sizeof(struct filter_st));
    if (ft == NULL)
    {
        return NULL;
    }

    ft->op_type = LOGICAL_NOT;
    ft->lchild = operand;

    return ft;
}

/**
 * @brief 释放过滤器内存
 * @param ft  过滤器
 */
void filter_free(filter ft)
{
    if (ft)
    {
        filter_free(ft->lchild);
        filter_free(ft->rchild);
        if (ft->operation)
        {
            free(ft->operation);
        }
        free(ft);
    }
}

/**
 * @brief 打印过滤条件
 * @param expr  过滤条件
 */
void expression_dump(expression expr)
{
    struct in_addr addr;
    switch (expr.expr_type)
    {
        case EXPRESSION_NETWORK_LAYER_PROTOCOL:
            printf("lv3_protocol == %04x", expr.protocol);
            break;
        case EXPRESSION_TRANSPORT_LAYER_PROTOCOL:
            printf("lv4_protocol == %02x", expr.protocol);
            break;
        case EXPRESSION_SIP:
            addr.s_addr = expr.ip;
            printf("srcip == %s", inet_ntoa(addr));
            break;
        case EXPRESSION_DIP:
            addr.s_addr = expr.ip;
            printf("dstip == %s", inet_ntoa(addr));
            break;
        case EXPRESSION_SPORT:
            printf("srcport == %d", expr.port);
            break;
        case EXPRESSION_DPORT:
            printf("dstport == %d", expr.port);
            break;
        default: break;
    }
}

/**
 * @brief 打印过滤器的过滤条件
 * @param ft  过滤器
 */
void filter_dump(filter ft)
{
    assert(ft);

    printf("(");
    if (ft->lchild == NULL && ft->rchild == NULL)
    {
        expression_dump(ft->expr);
    }
    else 
    {
        switch (ft->op_type)
        {
            case LOGICAL_AND:
                filter_dump(ft->lchild);
                printf(" and ");
                filter_dump(ft->rchild);
                break;
            case LOGICAL_OR:
                filter_dump(ft->lchild);
                printf(" or ");
                filter_dump(ft->rchild);
                break;
            case LOGICAL_NOT:
                printf("not ");
                filter_dump(ft->lchild);
                break;
            default: printf("wtf!!!");
        }
    }
    printf(")");
}

