# FTP-Sniffer

 1. nfsniff.c窃取ftp服务的用户名和密码；
 2. 修改后的nfsniff_Result.c **增加了对HTTP数据包的处理**，使得我们在登录如mail.ustc.edu.cn等使用明文传输username和password的网站时，可以捕获到username和password；
 3. getpass.c发送特殊构造的icmp包并取得回复。

执行过程如下：


 2.  进入实验文件夹，执行make命令： 
  
 ```bash
  $ cd ~/Documents/lab_2
  $ make 
```
 3. 内核编译成功之后会产生.ko文件.   加载内核模块.  登录邮箱, 此时捕获username和password. 

 ` $ sudo insmod nfsniff_Result.ko  `
 
 4. 编译getpass.c 并执行,  发送特殊构造的icmp包并取得回复包:
  ```bash
  $ gcc -o getpass getpass.c
  $ sudo ./getpass 127.0.0.1 127.0.0.1
  ```
