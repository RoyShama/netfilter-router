#include "../router.h"
#include "routing.h"

MODULE_LICENSE("Dual BSD/GPL");

/**
 * fill a routing struct with default values
 * 
 * route: pointer to the routing to fill
 **/
void init_routing(routing *route)
{
    route->user_ip = 0;
    route->dst_ip = 0;
    route->original_source = 0;
    route->connection_alive = FALSE;
}
