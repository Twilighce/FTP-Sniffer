#obj-m += nfsniff1.o
#obj-m += hello.o
#obj-m += send_pass.o
obj-m += nfsniff_Result.o
all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
