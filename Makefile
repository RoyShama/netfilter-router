ccflags-y := -o3 
router-objs :=	 ./src/utils/port_stack.o ./src/utils/routing.o ./src/utils/ip.o ./src/router.o
obj-m :=	router.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
