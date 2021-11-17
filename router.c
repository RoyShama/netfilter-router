#include "router.h"
#include "utils/port_stack.h"

MODULE_LICENSE("Dual BSD/GPL");

static struct nf_hook_ops nfho_pre_routing;
static struct nf_hook_ops nfho_post_routing;
static struct task_struct *kthread;
routing udp_arr[65536], tcp_arr[65536];
port_stack udp, tcp, udp_in_use, tcp_in_use, tem_udp, tem_tcp;

void init_routing(routing *r)
{
	r->user_ip = 0;
	r->dst_ip = 0;
	r->original_source = 0;
	r->connection_allive = FALSE;
}

void reset_arr(void)
{
	int i;
	for (i = 0; i < 65536; ++i)
	{
		init_routing(&udp_arr[i]);
		init_routing(&tcp_arr[i]);
	}
}

void print_ip(__u32 ip)
{
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	printk(KERN_INFO "%d.%d.%d.%d\n",
		   bytes[0], bytes[1], bytes[2], bytes[3]);
}

int find_original_source_udp(__u16 port, __u32 ip)
{
	int i;
	for (i = 1; i < 65536; ++i)
	{
		if (udp_arr[i].dst_ip == ip &&
			udp_arr[i].original_source == port)
		{
			return i;
		}
	}
	return 0;
}

int find_original_source_tcp(__u16 port, __u32 ip)
{
	int i;
	for (i = 0; i < 65536; ++i)
	{
		if (tcp_arr[i].dst_ip == ip &&
			tcp_arr[i].original_source == port)
		{
			return i;
		}
	}
	return 0;
}

void update_checksum(struct sk_buff *skb)
{
	struct iphdr *ip_header;
	ip_header = ip_hdr(skb);
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum_valid = 0;
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
	if ((ip_header->protocol == IPPROTO_TCP) || (ip_header->protocol == IPPROTO_UDP))
	{
		if (skb_is_nonlinear(skb))
		{
			skb_linearize(skb);
		}
		if (ip_header->protocol == IPPROTO_TCP)
		{
			struct tcphdr *tcpHdr;
			unsigned int tcplen;
			tcpHdr = tcp_hdr(skb);
			skb->csum = 0;
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
			udpHdr = udp_hdr(skb);
			skb->csum = 0;
			udplen = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
			udpHdr->check = 0;
			udpHdr->check = udp_v4_check(udplen, ip_header->saddr,
										 ip_header->daddr,
										 csum_partial((char *)udpHdr,
													  udplen, 0));
		}
	}
}

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

int connection_exist_post_tcp(struct sk_buff *sock_buff)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	int m_port;
	tcph = tcp_hdr(sock_buff);
	iph = (struct iphdr *)skb_network_header(sock_buff);
	m_port = find_original_source_tcp(tcph->source, iph->daddr);
	if (m_port != 0 && tcp_arr[m_port].user_ip == iph->saddr)
	{
		if (tcp_arr[m_port].original_source == tcph->source &&
			tcp_arr[m_port].dst_ip == iph->daddr)
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		m_port = find_original_source_tcp(tcph->dest, iph->saddr);
		if (tcp_arr[m_port].dst_ip == iph->saddr &&
			tcp_arr[m_port].user_ip == iph->daddr &&
			tcp_arr[m_port].original_source == tcph->dest)
		{
			return 2;
		}
	}
	return FALSE;
}

int connection_exist_post_udp(struct sk_buff *sock_buff)
{
	struct iphdr *iph;
	struct udphdr *udph;
	int m_port;
	udph = udp_hdr(sock_buff);
	iph = (struct iphdr *)skb_network_header(sock_buff);
	m_port = find_original_source_udp(udph->source, iph->daddr);
	if (m_port != 0 && udp_arr[m_port].user_ip == iph->saddr)
	{
		if (udp_arr[m_port].original_source == udph->source &&
			udp_arr[m_port].dst_ip == iph->daddr)
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		m_port = find_original_source_udp(udph->dest, iph->saddr);
		if (udp_arr[m_port].dst_ip == iph->saddr &&
			udp_arr[m_port].user_ip == iph->daddr &&
			udp_arr[m_port].original_source == udph->dest)
		{
			return 2;
		}
	}
	return FALSE;
}

void new_connection_tcp(struct sk_buff *sock_buff)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	int tem_tcp = pop(&tcp);
	tcph = tcp_hdr(sock_buff);
	push(&tcp_in_use, tem_tcp);
	iph = (struct iphdr *)skb_network_header(sock_buff);
	tcp_arr[tem_tcp].user_ip = iph->saddr;
	tcp_arr[tem_tcp].dst_ip = iph->daddr;
	tcp_arr[tem_tcp].original_source = tcph->source;
}

void new_connection_udp(struct sk_buff *sock_buff)
{
	struct iphdr *iph;
	struct udphdr *udph;
	int tem_udp = pop(&udp);
	push(&udp_in_use, tem_udp);
	udph = udp_hdr(sock_buff);
	iph = (struct iphdr *)skb_network_header(sock_buff);
	udp_arr[tem_udp].user_ip = iph->saddr;
	udp_arr[tem_udp].dst_ip = iph->daddr;
	udp_arr[tem_udp].original_source = udph->source;
}

void modify_packet_post_tcp(struct sk_buff *sock_buff)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	int m_port;
	tcph = tcp_hdr(sock_buff);
	iph = (struct iphdr *)skb_network_header(sock_buff);
	m_port = find_original_source_tcp(tcph->source, iph->daddr);
	iph->saddr = PUBLIC_IP;
	tcph->source = m_port;
	tcp_arr[m_port].connection_allive = TRUE;
}

void modify_packet_post_udp(struct sk_buff *sock_buff)
{
	struct iphdr *iph;
	struct udphdr *udph;
	int m_port;
	udph = udp_hdr(sock_buff);
	iph = (struct iphdr *)skb_network_header(sock_buff);
	m_port = find_original_source_udp(udph->source, iph->daddr);
	iph->saddr = PUBLIC_IP;
	udph->source = m_port;
	udp_arr[m_port].connection_allive = TRUE;
}

unsigned int post_routing_hook_func(void *priv, struct sk_buff *sock_buff, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	int connection_status;
	if (!is_ip(sock_buff))
	{
		return NF_ACCEPT;
	}
	iph = (struct iphdr *)skb_network_header(sock_buff);
	if (iph->saddr != PUBLIC_IP && iph->daddr != PUBLIC_IP)
	{
		if (iph->protocol == IPPROTO_TCP)
		{
			connection_status = connection_exist_post_tcp(sock_buff);
			if (connection_status == 2)
			{
				return NF_ACCEPT;
			}
			if (!connection_status)
			{
				new_connection_tcp(sock_buff);
			}
			modify_packet_post_tcp(sock_buff);
		}
		else if (iph->protocol == IPPROTO_UDP)
		{
			connection_status = connection_exist_post_udp(sock_buff);
			if (connection_status == 2)
			{
				return NF_ACCEPT;
			}
			if (!connection_status)
			{
				new_connection_udp(sock_buff);
			}
			modify_packet_post_udp(sock_buff);
		}
		update_checksum(sock_buff);
	}
	return NF_ACCEPT;
}

int connection_exist_pre_tcp(struct sk_buff *sock_buff)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	tcph = tcp_hdr(sock_buff);
	iph = (struct iphdr *)skb_network_header(sock_buff);
	if (iph->daddr == PUBLIC_IP)
	{
		if (tcp_arr[tcph->dest].original_source != 0 && tcp_arr[tcph->dest].dst_ip == iph->saddr)
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	return FALSE;
}

int connection_exist_pre_udp(struct sk_buff *sock_buff)
{
	struct iphdr *iph;
	struct udphdr *udph;
	udph = udp_hdr(sock_buff);
	iph = (struct iphdr *)skb_network_header(sock_buff);
	if (iph->daddr == PUBLIC_IP)
	{
		if (udp_arr[udph->dest].original_source != 0 && udp_arr[udph->dest].dst_ip == iph->saddr)
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	return FALSE;
}

void modify_packet_pre_tcp(struct sk_buff *sock_buff)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	tcph = tcp_hdr(sock_buff);
	iph = (struct iphdr *)skb_network_header(sock_buff);
	iph->daddr = tcp_arr[tcph->dest].user_ip;
	tcp_arr[tcph->dest].connection_allive = TRUE;
	tcph->dest = tcp_arr[tcph->dest].original_source;
}

void modify_packet_pre_udp(struct sk_buff *sock_buff)
{
	struct iphdr *iph;
	struct udphdr *udph;
	udph = udp_hdr(sock_buff);
	iph = (struct iphdr *)skb_network_header(sock_buff);
	iph->daddr = udp_arr[udph->dest].user_ip;
	udp_arr[udph->dest].connection_allive = TRUE;
	udph->dest = udp_arr[udph->dest].original_source;
}

unsigned int pre_routing_hook_func(void *priv, struct sk_buff *sock_buff, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	if (!is_ip(sock_buff))
	{
		return NF_ACCEPT;
	}

	iph = (struct iphdr *)skb_network_header(sock_buff);

	if (iph->daddr == PUBLIC_IP)
	{
		if (iph->protocol == IPPROTO_TCP)
		{
			if (connection_exist_pre_tcp(sock_buff))
			{
				modify_packet_pre_tcp(sock_buff);
			}
		}
		else if (iph->protocol == IPPROTO_UDP)
		{
			if (connection_exist_pre_udp(sock_buff))
			{
				modify_packet_pre_udp(sock_buff);
			}
		}
		update_checksum(sock_buff);
	}
	return NF_ACCEPT;
}

void free_ports(void)
{
	int tem_port;
	tem_udp.head = 0;
	tem_tcp.head = 0;

	tem_port = pop(&udp_in_use);
	while (tem_port != -1)
	{
		if (udp_arr[tem_port].connection_allive)
		{
			udp_arr[tem_port].connection_allive = FALSE;
			push(&tem_udp, tem_port);
		}
		else
		{
			push(&udp, tem_port);
		}
		tem_port = pop(&udp_in_use);
	}

	tem_port = pop(&tcp_in_use);
	while (tem_port != -1)
	{
		if (tcp_arr[tem_port].connection_allive)
		{
			tcp_arr[tem_port].connection_allive = FALSE;
			push(&tem_tcp, tem_port);
		}
		else
		{
			push(&tcp, tem_port);
		}
		tem_port = pop(&tcp_in_use);
	}

	tem_port = pop(&tem_udp);
	while (tem_port != -1)
	{
		push(&udp_in_use, tem_port);
		tem_port = pop(&tem_udp);
	}

	tem_port = pop(&tem_tcp);
	while (tem_port != -1)
	{
		push(&tcp_in_use, tem_port);
		tem_port = pop(&tem_tcp);
	}
}

int free_ports_forever(void *data)
{
	int i = 1;
	while (!kthread_should_stop())
	{
		msleep(10000);
		if (i == 30)
		{
			free_ports();
			i = 1;
		}
		else
		{
			++i;
		}
	}
	return 0;
}

static int __init initialize(void)
{
	reset_arr();
	init_open_port(&udp);
	init_open_port(&tcp);
	udp_in_use.head = 0;
	tcp_in_use.head = 0;

	nfho_pre_routing.hook = &pre_routing_hook_func;
	nfho_pre_routing.hooknum = NF_INET_PRE_ROUTING;
	nfho_pre_routing.pf = PF_INET;
	nfho_pre_routing.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfho_pre_routing);

	nfho_post_routing.hook = &post_routing_hook_func;
	nfho_post_routing.hooknum = NF_INET_POST_ROUTING;
	nfho_post_routing.pf = PF_INET;
	nfho_post_routing.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfho_post_routing);

	kthread = kthread_create(free_ports_forever, NULL, "router_kthread");
	wake_up_process(kthread);

	return 0;
}

static void __exit teardown(void)
{
	nf_unregister_net_hook(&init_net, &nfho_pre_routing);
	nf_unregister_net_hook(&init_net, &nfho_post_routing);
	kthread_stop(kthread);
}

module_init(initialize);
module_exit(teardown);
