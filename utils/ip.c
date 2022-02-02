#include "../router.h"
#include "ip.h"

/**
 * print an ip addres in a human readable way
 * 
 * ip: number of the ip addres to print
 **/
void print_ip(__u32 ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printk(KERN_ALERT "%d.%d.%d.%d\n",
           bytes[0], bytes[1], bytes[2], bytes[3]);
}

//TODO add diffrent functions for tcp and udp
//(check if can do that in one generic function for the fourth layer)
/**
 * update th checksum of a packet including its 4th layer
 * 
 * sock_buff: pointer to the buffer of the packet to update
 **/
void update_checksum(struct sk_buff *sock_buff)
{
    struct iphdr *ip_header;
    ip_header = ip_hdr(sock_buff);
    sock_buff->ip_summed = CHECKSUM_NONE;
    sock_buff->csum_valid = 0;
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
    if ((ip_header->protocol == IPPROTO_TCP) || (ip_header->protocol == IPPROTO_UDP))
    {
        if (skb_is_nonlinear(sock_buff))
        {
            skb_linearize(sock_buff);
        }
        if (ip_header->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcpHdr;
            unsigned int tcplen;
            tcpHdr = tcp_hdr(sock_buff);
            sock_buff->csum = 0;
            tcplen = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
            tcpHdr->check = 0;
            tcpHdr->check = tcp_v4_check(
                tcplen,
                ip_header->saddr,
                ip_header->daddr,
                csum_partial((char *)tcpHdr, tcplen, 0));
        }
        else if (ip_header->protocol == IPPROTO_UDP)
        {
            struct udphdr *udpHdr;
            unsigned int udplen;
            udpHdr = udp_hdr(sock_buff);
            sock_buff->csum = 0;
            udplen = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
            udpHdr->check = 0;
            udpHdr->check = udp_v4_check(udplen, ip_header->saddr,
                                         ip_header->daddr,
                                         csum_partial((char *)udpHdr,
                                                      udplen, 0));
        }
    }
}

//TODO: i dont like the icmp thing
//TODO: why by value?
/**
 * check if packet is ip
 * 
 * sock_buff: pointer to the packet buffer to check
 **/
int is_ip(struct sk_buff *sock_buff)
{
    struct iphdr *iph;
    if (!sock_buff)
    {
        return FALSE;
    }
    iph = (struct iphdr *)skb_network_header(sock_buff);
    if (!iph)
    {
        return FALSE;
    }
    if (iph->protocol == IPPROTO_ICMP)
    {
        return FALSE;
    }
    return TRUE;
}