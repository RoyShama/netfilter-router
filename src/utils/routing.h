#ifndef ROUTING_H
#define ROUTING_H

#include <linux/module.h>
#include <linux/kernel.h>


// TODO: change from three tuple to four tuple
/**
 * represent tcp/udp connection between computers
 **/
typedef struct Routing {
    __u32 user_ip;         /* the ip address of the computer in the private network*/
    __u32 dst_ip;          /* the ip address of the computer in the www network*/
    __u16 original_source; /* the port of the computer in the private network*/
    int connection_alive;  /* was the connection was in use recently?*/
} routing;


void init_routing(routing *r);


#endif