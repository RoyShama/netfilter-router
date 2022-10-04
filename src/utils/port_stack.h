#ifndef PORT_STACK_H
#define PORT_STACK_H

#include <linux/kernel.h>
#include <linux/module.h>


// TODO: make the stack head 2^16
/**
 * stack of ports, used to track the server's ports
 **/
typedef struct PortStack {
    __u16 port_arr[32768]; /* the ports represented by their address*/
    int head;               /* the head of the stack*/
} port_stack;


int pop(port_stack *stack);


void push(port_stack *stack, __u16 port);


void init_open_port(port_stack *stack);


#endif