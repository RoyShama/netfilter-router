#include "port_stack.h"

MODULE_LICENSE("Dual BSD/GPL");


int pop(port_stack* stack){
	if(stack->head > -1){
		stack->head += -1;
		return stack->port_arr[stack->head ];
	}
	return -1;
}


void push(port_stack* stack, __u16 port){
	stack->port_arr[stack->head ] = port;
	++stack->head;
}


void init_open_port(port_stack* stack){
	int i;
	__u16 port = 32768;
	stack->head = 0;
	for(i = 0; i < 32765; ++i){
		push(stack,port);
		++port;
	}
}