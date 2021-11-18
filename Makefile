ccflags-y := -o3 
router-objs :=	router.o ./utils/port_stack.o ./utils/routing.o ./utils/ip.o
obj-m :=	router.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean