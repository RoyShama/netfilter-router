#ifndef IP_H
#define IP_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


void print_ip(__u32 ip);


void update_checksum(struct sk_buff *skb);


int is_ip(struct sk_buff *sock_buff);


#endif