# FTP-Sniffer
 
 Linux下，基于内核模块的FTP密码嗅探器。
 
 需要两台虚拟机：
 - 一台作为入侵者，getpass.c与nfsniff.c协同使用，nfsniff.c窃取username和password，执行getpass.c获取username和password；
 - 一台作为受害者，登录ftp服务器，sendpass.c与getpass1.c协同使用，sendpass.c在得到一个特殊构造的ICMP包（比如一个足够大的ping包时），发送username和password。
 
---
 修改后，只需一台虚拟机，可以在浏览器上登录服务时窃取密码，
 主要是在nfsniff_Result.c **增加了对HTTP数据包的处理**，在我们登录如mail.ustc.edu.cn等使用明文传输username和password的**网站**时，可以捕获到username和password；
 原理方面看这里：https://twilighce.github.io/2017/01/01/My-Netfilter/#more
 
**执行过程如下**：


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
