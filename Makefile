ccflags-y := -o3
router2-objs :=	router.o
obj-m :=	router2.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
