#include "port_stack.h"

MODULE_LICENSE("Dual BSD/GPL");


// TODO: is -1 really a smart idea?
/**
 * safe pop from port_stack 
 * 
 * stack: pointer to the stack that you want to get the top value from
 * 
 * return: the top value and if the stack is empty return -1
 **/
int pop(port_stack *stack) {
    if (stack->head > -1) {
        stack->head += -1;
        return stack->port_arr[stack->head];
    }
    return -1;
}


// TODO: make the push safe
/**
 * unsafe push to a stack
 * 
 * stack: pointer to the stack that you want to push into
 * port: the port address that you want to save
 **/
void push(port_stack *stack, __u16 port) {
    stack->port_arr[stack->head] = port;
    ++stack->head;
}


/**
 * fill the stack with values from 32768 to 2^16-1
 * 
 * stack: pointer to the stack that you want to initalize
 **/
void init_open_port(port_stack *stack) {
    int i;
    __u16 port = 32768;
    stack->head = 0;
    for (i = 0; i < 32765; ++i) {
        push(stack, port);
        ++port;
    }
}