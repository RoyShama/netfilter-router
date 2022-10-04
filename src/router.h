#ifndef ROUTER_H
#define ROUTER_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#define FALSE 0
#define TRUE !FALSE
#define swap_endian(num) ((num >> 24) & 0xff) | ((num << 8) & 0xff0000) | ((num >> 8) & 0xff00) | ((num << 24) & 0xff000000)
// TODO: make public ip dynamic
#define PUBLIC_IP ((__u32)swap_endian(2886994434))

#endif