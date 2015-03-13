#include <linux/ip.h>             
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/netdevice.h>      
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h> 
#include <linux/skbuff.h>         
#include <linux/udp.h>
#include <linux/printk.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <linux/tcp.h>      
#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
              
static struct nf_hook_ops netfilter_ops; 
unsigned char *ssh_port_number = "\x00\x16";
unsigned char *http_port_number = "\x00\x50";                       
static unsigned char *ip_address_web_server = "\xC0\xA8\x02\x01"; 
static unsigned char *ip_address_remote_client ="\xC0\xA8\x03\x02";  ///to be modified later
    
                      
struct sk_buff *sock_buff;                              
struct iphdr *ip_header;
struct tcphdr *tcp_header;
struct icmphdr *icmp_header;     
void DispIP(unsigned int address)
{
	unsigned int byte[4];
	int i;
	for(i=0;i<=3;i++)
	{
		byte[i]=(address >> (i*8)) & 0xFF;
	}
	printk("%d.%d.%d.%d",byte[0],byte[1],byte[2],byte[3]);
} 
                        
unsigned int main_hook(unsigned int hooknum,
                  struct sk_buff **skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
 
ip_header = (struct iphdr *)(skb_network_header(skb));            ///extracting ip header
tcp_header = (struct tcphdr *)(skb_transport_header(skb));      ////extracting tcp header
if(!skb){ return NF_ACCEPT;}                   

 
if(ip_header->protocol ==1)
{

icmp_header = (struct icmphdr *)(skb_transport_header(skb));

    if(icmp_header->type ==8)  
    {
         if(ip_header->daddr == *(unsigned int*)(ip_address_remote_client))
         {
         return NF_ACCEPT;
         }
         else 
         {  if(ip_header->daddr == *(unsigned int*)(ip_address_web_server))
            {
            return NF_ACCEPT;
            }
            else 
            {
            printk(KERN_INFO "Dropped. Reason: Illegal icmp request, Source IP: ");
	    DispIP((unsigned int)(ip_header->saddr));
	    printk(KERN_INFO "Dest IP: ");
	    DispIP((unsigned int)(ip_header->daddr));
	    printk(KERN_INFO "\n");
            return NF_DROP;
            }
         }
     }
    else 
    {
    return NF_ACCEPT;
    }
} 
else 
{
     if(ip_header->saddr == *(unsigned int*)(ip_address_remote_client)) // can check dest addr instead
     {
        if((tcp_header->dest) == *(unsigned short*)ssh_port_number)
        {
        printk(KERN_INFO "Dropped. Reason: SSH not allowed to network. Source IP: ");
	DispIP((unsigned int)(ip_header->saddr));
	printk(KERN_INFO "Dest IP: ");
	DispIP((unsigned int)(ip_header->daddr));
	printk(KERN_INFO "\n");
        return NF_DROP;
        }
        else
        {
           if((tcp_header->dest) == *(unsigned int*)http_port_number)
           {
	      if(ip_header->daddr == *(unsigned int*)(ip_address_web_server))
	      {
              return NF_ACCEPT;
	      }
              else{
              printk(KERN_INFO "Dropped. Reason: Illegal HTTP request. Source IP: ");
	      DispIP((unsigned int)(ip_header->saddr));
	      printk(KERN_INFO "Dest IP: ");
	      DispIP((unsigned int)(ip_header->daddr));
	      printk(KERN_INFO "\n");
              return NF_DROP;
              }
	   }
           else 
           {
           return NF_ACCEPT;
           }
        }
      } 
      else 
      { 
      return NF_ACCEPT;
      }
}
return NF_ACCEPT;
}
int init_module()
{
        netfilter_ops.hook              =       main_hook;
        netfilter_ops.pf                =       PF_INET;        
        netfilter_ops.hooknum           =       NF_INET_PRE_ROUTING;
        netfilter_ops.priority          =       NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops);
        
return 0;
}
void cleanup_module() { nf_unregister_hook(&netfilter_ops); }


