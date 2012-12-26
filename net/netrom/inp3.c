/*
 *	INP3 007
 *
 *	Copyright 2003, 2004 , Jeroen Vreeken (pe1rxq@amsat.org)
 *
 *	This module:
 *		This module is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	I do NOT grant permission to export any of these functions to 
 *	non free modules, so don't bother to ask....
 */

#ifdef CONFIG_NETROM_INP
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/errno.h>
#include <linux/net.h>
#include <linux/time.h>
#include <linux/kthread.h>
#include <net/ax25.h>
#include <net/arp.h>
#include <net/netrom.h>

#define INPVERSION "007"

#define info(format, arg...) printk(KERN_INFO __FILE__ ": " format "\n" "", ## arg)

#define INP3D_INTERVAL HZ*60
#define L3RTT_INTERVAL 5
#define RIF_INTERVAL 24*60
#define L3RTT_MTU 200

#define MAX_RIP 10

/* AX.25 address used for l3rtt packets */
ax25_address inp3_l3rtt_addr={{'L'<<1, '3'<<1, 'R'<<1, 'T'<<1, 'T'<<1, 0x40, 0}};

static int kinp3d_running=0;
static struct task_struct *kinp3d_task;
static int kinp3d_rifcount=0;

#define hopsmin(hops) ((hops)<1 ? 1 : (hops))
#define qual2hops(qual) ((256-(qual))/8+1)

inline int rtt2qual(int rtt, int hops)
{
	int qual;
	
	if (rtt>=TT_HORIZON)
		return 0;
	if (hops>=255)
		return 0;
	
	qual=254-(rtt/20);
	if (qual > 256-hops)
		qual=254-hops;
	if (qual < 1)
		qual=0;
	return qual;
}

inline int infotype(int ltt, int tt)
{
	if (tt>=TT_HORIZON) {
	        if (ltt!=TT_HORIZON)
			    return -1;
		else
		        return 0;
	}
	if (tt > ltt)
		return -1;

	if ((tt*5 < ltt*4) && (ltt-tt > 10))
		return 1;

	return 0;
}

int inp3_set_mnem(ax25_address *call, const char *mnemonic)
{
	struct net_device *dev;
	struct nr_dev_priv *priv;

	if ((dev = nr_dev_get(call)) == NULL)
		return -EINVAL;
	
	write_lock(&dev_base_lock);
	priv = (struct nr_dev_priv *)netdev_priv(dev);
	memcpy(priv->mnemonic, mnemonic, 6);
	write_lock(&dev_base_lock);

	dev_put(dev);

	return 0;
}

int inp3_get_mnem(ax25_address *call, char *mnemonic)
{
	struct net_device *dev;
	struct nr_dev_priv *priv;

	if ((dev = nr_dev_get(call)) == NULL)
		return -EINVAL;

	read_lock(&dev_base_lock);
	priv = (struct nr_dev_priv *)netdev_priv(dev);
	memcpy(mnemonic, priv->mnemonic, 7);
	read_unlock(&dev_base_lock);
	dev_put(dev);
	
	return 0;
}

static char *inp3_first_mnemonic(void)
{
	static char mnemonic[7];
	struct net_device *dev;
	struct nr_dev_priv *priv;

	if ((dev = nr_dev_first()) == NULL)
		return NULL;
	priv = (struct nr_dev_priv *)netdev_priv(dev);
	if (priv->mnemonic[0])
		memcpy(mnemonic, priv->mnemonic, 7);
	else
		memcpy(mnemonic, "#none", 6);
	dev_put(dev);
	
	return mnemonic;
}

inline static struct sk_buff *new_rif_skb(struct nr_neigh *nr_neigh)
{
	struct sk_buff *skb;
	int axlen=nr_neigh->dev->hard_header_len;

	if ((skb=alloc_skb(axlen + 222, GFP_ATOMIC)) != NULL) {
		skb_reserve(skb, axlen-1);
		skb->transport_header=skb->data;
		*skb_put(skb, 1)=AX25_P_NETROM;
		*skb_put(skb, 1)=0xff; /* RIF signature */
		return skb;
	}
	return NULL;
}

inline static void rif_tx(struct nr_neigh *nr_neigh, struct sk_buff *skb)
{
	struct net_device *dev;
	ax25_cb *ax25s;

	/* only to INP3 nodes */
	if (nr_neigh->inp_state==NR_INP_STATE_0) {
		kfree_skb(skb);
		return;
	}
	
	if ((dev=nr_dev_first())==NULL) {
		kfree_skb(skb);
		return;
	}

	ax25s=ax25_send_frame(skb, 256, (ax25_address *)dev->dev_addr,
	    &nr_neigh->callsign, nr_neigh->digipeat, nr_neigh->dev);
	if (ax25s && nr_neigh->ax25) {
		ax25_cb_put(nr_neigh->ax25);
	}
	if (ax25s)
		nr_neigh->ax25=ax25s;
	else
		kfree_skb(skb);
	dev_put(dev);
}

inline void inp3_ltt_update(int all, int neg)
{
	struct nr_node *nr_node;
	struct hlist_node *node;
	int tt;

	spin_lock_bh(&nr_node_list_lock);
	nr_node_for_each(nr_node, node, &nr_node_list) {
		nr_node_lock(nr_node);
		if (nr_node->routes[0].neighbour->inp_state==NR_INP_STATE_INP)
			tt=nr_node->routes[0].tt+nr_node->routes[0].neighbour->rtt;
		else
			tt=qual2rtt(nr_node->routes[0].quality);
		if ((ttlimit(tt)>nr_node->ltt) ||
		    (!neg && infotype(nr_node->ltt, tt)) ||
		    all)
			nr_node->ltt=ttlimit(tt);
		nr_node_unlock(nr_node);
	}
	spin_unlock_bh(&nr_node_list_lock);
}

static int inp3_rif_tx(struct nr_neigh *nr_neigh, int all) {
	struct nr_node *nr_node;
	struct hlist_node *node;
	struct sk_buff *skb;
	unsigned char *rip=NULL;
	int ripcount;
	int route;
	int tt;
	int hops;

	skb=new_rif_skb(nr_neigh);
	if (!skb)
		return -1;
	ripcount=0;

	if (all) {
		struct net_device *dev;
		struct nr_dev_priv *priv;
		/* first a few rips about ourself */
		read_lock(&dev_base_lock);
		for_each_netdev(&init_net, dev) {
			if ((dev->flags  & IFF_UP) && dev->type==ARPHRD_NETROM) {
				rip=skb_put(skb, 12);
				if (rip < 0x100 || dev->dev_addr < 0x100) {
					printk(KERN_CRIT "shit: %p %p\n", rip, dev->dev_addr);
				} else 
				memcpy(rip, (ax25_address *)dev->dev_addr, 7);
				*(rip+7)=1;	/* hops */
				*(rip+8)=0;	/* tt */
				*(rip+9)=0;	/* tt */
				priv=(struct nr_dev_priv *)netdev_priv(dev);
				*(rip+10)=2+strlen(priv->mnemonic);
				*(rip+11)=0;
				rip=skb_put(skb, strlen(priv->mnemonic)+1);
				strcpy(rip, priv->mnemonic);
				*(rip+strlen(priv->mnemonic))=0; /* eop */
				ripcount++;
			}
		}
		read_unlock(&dev_base_lock);
	}
	spin_lock_bh(&nr_node_list_lock);
	nr_node_for_each(nr_node, node, &nr_node_list) {
		nr_node_lock(nr_node);
		route=nr_node->count;
		/* use alternative reverse if routes[0] is backward */
		if (nr_node->routes[0].neighbour!=nr_neigh)
			route=0;
		else if (nr_node->count > 1)
			route=1;
		else {
			nr_node_unlock(nr_node);
			continue;
		}
		if (nr_node->routes[route].neighbour->inp_state==NR_INP_STATE_INP) {
			hops=nr_node->routes[route].hops;
			tt=nr_node->routes[route].tt+nr_node->routes[route].neighbour->rtt;
		} else {
			hops=qual2hops(nr_node->routes[route].quality);
			tt=qual2rtt(nr_node->routes[route].quality);
		}
		if (hops+1<256 && (infotype(nr_node->ltt, tt) || all)) {
			rip=skb_put(skb, 12);
			if (rip < 0x100 || &nr_node->callsign < 0x100) {
				printk(KERN_CRIT "shit2: %p %p\n", rip, &nr_node->callsign);
			} else 
			memcpy(rip, &nr_node->callsign, 7);
			*(rip+7)=hopsmin(hops)+1;
			*(rip+8)=ttlimit(tt) / 256;
			*(rip+9)=ttlimit(tt) & 0xff;
			*(rip+10)=strlen(nr_node->mnemonic)+2;
			*(rip+11)=0x00;
			rip=skb_put(skb, strlen(nr_node->mnemonic)+1);
			strcpy(rip, nr_node->mnemonic);
			*(rip+strlen(nr_node->mnemonic))=0;
			ripcount++;
		}
		if (ripcount>=MAX_RIP) {
			rif_tx(nr_neigh, skb);
			skb=new_rif_skb(nr_neigh);
			if (!skb) {
				nr_node_unlock(nr_node);
				spin_unlock_bh(&nr_node_list_lock);
				return -1;
			}
			ripcount=0; 
		}
		nr_node_unlock(nr_node);
	}
	spin_unlock_bh(&nr_node_list_lock);
	if (ripcount)
		rif_tx(nr_neigh, skb);
	else
		kfree_skb(skb);
	return 0;
}

/*
	Sends negative info about neg_nodes to neigh_list.
	Expects parsing of neigh_list to be safe.
 */
void inp3_nodes_neg(struct nr_node *neg_node[], int neg_nodes, 
	struct nr_neigh *origin_neigh, struct hlist_head *neigh_list)
{
	int i;
	int route;
	int tt;
	int hops;
	struct nr_neigh *nr_neigh;
	struct hlist_node *node;

	nr_neigh_for_each(nr_neigh, node, neigh_list) {
		int ripcount=0;
		unsigned char *rip;
		struct sk_buff *skb;
		
		skb=new_rif_skb(nr_neigh);
		if (!skb) {
			return;
		}
		for (i=0; i<neg_nodes; i++) {
			nr_node_lock(neg_node[i]);
			if (neg_node[i]->ltt>=TT_HORIZON) {
				nr_node_unlock(neg_node[i]);
				continue;
			}
			rip=skb_put(skb, 7);
			memcpy(rip, &neg_node[i]->callsign, 7);
			route=neg_node[i]->count;
			if (neg_node[i]->routes[0].neighbour->rtt+neg_node[i]->routes[0].tt<TT_HORIZON &&
			    neg_node[i]->routes[0].neighbour!=nr_neigh) {
				route=0;
			} else if (neg_node[i]->count > 1 && neg_node[i]->routes[1].neighbour!=nr_neigh) {
				route=1;
			} else if (neg_node[i]->count > 2) {
				route=2;
			}
			if (route!=neg_node[i]->count) {
				if (neg_node[i]->routes[route].neighbour->inp_state==NR_INP_STATE_INP) {
					hops=neg_node[i]->routes[route].hops;
					tt=neg_node[i]->routes[route].tt+neg_node[i]->routes[route].neighbour->rtt;
				} else {
					hops=qual2hops(neg_node[i]->routes[route].quality);
					tt=qual2rtt(neg_node[i]->routes[route].quality);
				}
			} else {
				hops=254;
				tt=TT_HORIZON;
			}
			if ((tt>=TT_HORIZON && origin_neigh==nr_neigh) ||
			    tt<=neg_node[i]->ltt) {
				nr_node_unlock(neg_node[i]);
				continue;
			}
			rip=skb_put(skb, 4);
			*(rip+0)=hopsmin(hops)+1;
			*(rip+1)=ttlimit(tt) / 256;
			*(rip+2)=ttlimit(tt) & 0xff;
			*(rip+3)=0;
			ripcount++;
			nr_node_unlock(neg_node[i]);
		}
		if (ripcount)
			rif_tx(nr_neigh, skb);
		else
			kfree_skb(skb);
	}
	for (i=0; i<neg_nodes;  i++) {
		for (route=neg_node[i]->count-1; route>=0; route--) {
			if (neg_node[i]->routes[route].neighbour->rtt+neg_node[i]->routes[route].tt>=TT_HORIZON) {
				nr_node_hold(neg_node[i]);
				nr_del_node_found(neg_node[i], neg_node[i]->routes[route].neighbour);
				route=-1;
			}
		}
		nr_node_put(neg_node[i]);
	}
	inp3_ltt_update(0, 1);
}

void inp3_route_neg(struct nr_neigh *nr_neigh)
{
	struct nr_node *nr_node;
	struct nr_node **neg_node;
	struct hlist_node *node, *nodet;
	int neg_nodes=0;

	neg_node=kmalloc(sizeof(struct nr_node *)*MAX_RIPNEG, GFP_ATOMIC);
	if (!neg_node) {
		nr_neigh_put(nr_neigh);
		return;
	}
	spin_lock_bh(&nr_neigh_list_lock);
	spin_lock_bh(&nr_node_list_lock);
	nr_node_for_each_safe(nr_node, node, nodet, &nr_node_list) {
		nr_node_lock(nr_node);
		if (nr_node->routes[0].neighbour==nr_neigh) {
			if (neg_nodes>=MAX_RIPNEG) {
				inp3_nodes_neg(neg_node, neg_nodes, nr_neigh, &nr_neigh_list);
				neg_nodes=0;
			}
			nr_node_hold(nr_node);
			neg_node[neg_nodes]=nr_node;
			neg_nodes++;
		}
		nr_node_unlock(nr_node);
	}
	if (neg_nodes) {
		inp3_nodes_neg(neg_node, neg_nodes, nr_neigh, &nr_neigh_list);
		neg_nodes=0;
	}
	kfree(neg_node);
	spin_unlock_bh(&nr_node_list_lock);
	spin_unlock_bh(&nr_neigh_list_lock);
	return;
}

int inp3_rif_rx(struct sk_buff *skb, ax25_cb *ax25)
{
	struct nr_node **neg_node;
	int neg_nodes=0;
	ax25_address *nodecall=NULL;
	struct nr_neigh *nr_neigh=NULL;
	struct nr_node *nr_node=NULL;
	int hops=0;
	int tt=0;
	int qual=0;
	unsigned char *dptr;
	unsigned char mnemonic[7];
	int i;
	int optlen, opttype, oldroute, oldtt;

	nr_neigh=nr_neigh_get_dev(&ax25->dest_addr, ax25->ax25_dev->dev);
	if (!nr_neigh)
		return 1;
	neg_node=kmalloc(sizeof(struct nr_node *)*MAX_RIPNEG, GFP_ATOMIC);
	if (!neg_node) {
		nr_neigh_put(nr_neigh);
		return 1;
	}
	dptr=skb->data+1;
	/* continue until end of packet */
	while (dptr<skb->data+skb->len-10) {
		mnemonic[0]=0;
		nodecall=(ax25_address *)dptr;
		dptr+=7;
		hops=*dptr++;
		tt=(dptr[0]<<8)+dptr[1];
		dptr+=2;
		while (*dptr && dptr+*dptr<skb->data+skb->len) {
			optlen=*dptr;
			opttype=*(dptr+1);
			if (opttype==0x00) {
				if (optlen-2>6)
					optlen=8;
				memcpy(mnemonic, dptr+2, optlen-2);
				mnemonic[optlen-2]=0;
			}
			dptr+=*dptr;
		}
		dptr++;
		nr_neigh->inp_state=NR_INP_STATE_INP;
		/* Over the horizon? */
		if (tt+nr_neigh->rtt>TT_HORIZON || hops==255)
			tt=TT_HORIZON;
		qual=rtt2qual(nr_neigh->rtt+tt, hops);
		/* Make sure node exists */
		nr_add_node(nodecall, mnemonic, &nr_neigh->callsign,
		    nr_neigh->digipeat, nr_neigh->dev,
		    nr_neigh->inp_state?qual:0,
		    sysctl_netrom_obsolescence_count_initialiser);
		nr_node=nr_node_get(nodecall);
		if (!nr_node)
			break;
		nr_node_lock(nr_node);
		for (i=0; i<nr_node->count; i++)
			if (nr_node->routes[i].neighbour==nr_neigh)
				break;
		oldroute=i;
		oldtt=nr_node->routes[0].neighbour->rtt+nr_node->routes[0].tt;
		if (i < nr_node->count) {
			nr_node->routes[i].tt=tt;
			nr_node->routes[i].hops=hops;
			nr_node->routes[i].quality=qual;
		}
		if (!nr_neigh->inp_state) {
			nr_node_unlock(nr_node);
			nr_node_put(nr_node);
			break;
		}
		/* Call nr_sort_node in case a better route is now known */
		nr_sort_node(nr_node);
		nr_node_unlock(nr_node);
		/* Is it negative information? */
		if ((i==0 && infotype(nr_node->ltt, 
		    nr_node->routes[0].tt+nr_node->routes[0].neighbour->rtt)==-1)) {
			if (neg_nodes>=MAX_RIPNEG) {
				spin_lock_bh(&nr_neigh_list_lock);
				inp3_nodes_neg(neg_node, neg_nodes, nr_neigh, &nr_neigh_list);
				spin_unlock_bh(&nr_neigh_list_lock);
				neg_nodes=0;
			}
			neg_node[neg_nodes]=nr_node;
			neg_nodes++;
			break;
		}
		/* If its positive information we don't propagate it yet. */
		nr_node_put(nr_node);
	}
	if (neg_nodes) {
		spin_lock_bh(&nr_neigh_list_lock);
		inp3_nodes_neg(neg_node, neg_nodes, nr_neigh, &nr_neigh_list);
		spin_unlock_bh(&nr_neigh_list_lock);
	}
	kfree(neg_node);
	nr_neigh_put(nr_neigh);
	return 0;
}

/*
	According to the INP3 spec we are free to put pretty much anything in
	the l3rtt measurement frames....
	However atleast XNET seams to be picky on what it accepts.
	Both XNET and TNN currently use a format they describe as LEVEL3_V2.1
	however there doesn't seem to be any format description of this format.
	Here we try to emulate that format as close as possible...
 */

int inp3_l3rtt_tx(struct nr_neigh *nr_neigh)
{
	struct ax25_cb *ax25s;
	struct net_device *dev;
	struct sk_buff *skb;
	struct timeval tv;
	unsigned char *rtt_data;

	if ((dev=nr_dev_first()) == NULL)
		return 0;

	skb=alloc_skb(nr_neigh->dev->hard_header_len + L3RTT_MTU+1, GFP_ATOMIC);
	if (!skb) {
		dev_put(dev);
		printk(KERN_CRIT "inp3_l3rtt_tx: alloc_skb failed\n");
		return 0;
	}
	skb_reserve(skb, nr_neigh->dev->hard_header_len);
	skb->transport_header=skb->data;

	rtt_data=skb_put(skb, L3RTT_MTU+1);
	if (!rtt_data) {
		dev_put(dev);
		printk(KERN_CRIT "inp3_l3rtt_tx: skb_put failed\n");
		kfree_skb(skb);
		return 0;
	}
	rtt_data[0]=AX25_P_NETROM;
	memset(rtt_data+1, 0x20, L3RTT_MTU);
	memcpy(rtt_data+1, dev->dev_addr, 7);
	memcpy(rtt_data+7+1, &inp3_l3rtt_addr, 7);
	rtt_data[14+1]=0x02; /* ttl */
	rtt_data[15+1]=0x00;
	rtt_data[16+1]=0x00;
	rtt_data[17+1]=0x00;
	rtt_data[18+1]=0x00;
	rtt_data[19+1]=NR_INFO;
	do_gettimeofday(&tv);
	/* Has to stay within L3RTT_MTU! */
	rtt_data[20+1+sprintf(rtt_data+20+1, 
	    "L3RTT: %10d %10d %10d %10d %-6s %11s %s $M%d $N",
	    (int)tv.tv_sec, 
	    nr_neigh->rtt, 
	    nr_neigh->rtt, 
	    (int)tv.tv_usec,
	    inp3_first_mnemonic(), 
	    "LEVEL3_V2.1", "LINUX" INPVERSION, 
	    TT_HORIZON
	)]=0x20;
	rtt_data[L3RTT_MTU]=0x0d;

		
	ax25s=ax25_send_frame(skb, 256, (ax25_address *)dev->dev_addr,
	    &nr_neigh->callsign, nr_neigh->digipeat, nr_neigh->dev);
	if (ax25s && nr_neigh->ax25) {
		ax25_cb_put(nr_neigh->ax25);
	}
	if (!ax25s) {
		kfree_skb(skb);
	} else {
		nr_neigh->ax25=ax25s;
	}
	dev_put(dev);
	return 1;
}

int inp3_l3rtt_rx(struct sk_buff *skb, ax25_cb *ax25)
{
	int neg_nodes=0;
	struct nr_node **neg_node;
	ax25_address *nr_src;
	struct hlist_node *node, *node2;
	struct nr_neigh *nr_neigh=NULL;
	struct nr_node *nr_node=NULL;
	struct net_device *dev;
	struct sk_buff *skbret;
	unsigned char *dptr;
	struct timeval tv, tvret;
	char *rttdata;
	int rtt;
	int qual;
	int i;
	int oldroute=0, oldtt=0;

	nr_src=(ax25_address *)(skb->data);

	/* Shouldn't happen! */
	if (!ax25) {
		info("Should not get my own l3rtt frames!!!");
		return 0;
	}
	
	if ((dev=nr_dev_first()) == NULL)
		return 0;

	/* Is it a reply to one of our l3rtt frames? */
	if (!ax25cmp(nr_src, (ax25_address *)dev->dev_addr)) {
		if (skb->len < 29) {
			dev_put(dev);
			return 0;
		}
		rttdata=skb->data;
		/* Add terminating null */
		rttdata[skb->len-1]=0;
		dptr=rttdata+7+20;
		while(*dptr==0x20) dptr++;
		tvret.tv_sec=simple_strtoul(dptr, (char **)(&dptr), 0);
		while(*dptr==0x20) dptr++;
		i=simple_strtoul(dptr, (char **)(&dptr), 0);
		while(*dptr==0x20) dptr++;
		i=simple_strtoul(dptr, (char **)(&dptr), 0);
		while(*dptr==0x20) dptr++;
		tvret.tv_usec=simple_strtoul(dptr, (char **)(&dptr), 0);
		do_gettimeofday(&tv);
		rtt=((tv.tv_sec-tvret.tv_sec)*1000+(tv.tv_usec+10000)/1000)/20;
		if (!rtt)
			rtt=1;
		nr_node=nr_node_get(&ax25->dest_addr);
		if (!nr_node) {
			dev_put(dev);
			return 0;
		}
		nr_neigh=nr_neigh_get_dev(&ax25->dest_addr, ax25->ax25_dev->dev);
		if (!nr_neigh) {
			nr_node_put(nr_node);
			dev_put(dev);
		}
		nr_node_lock(nr_node);
		for (i=0; i<nr_node->count; i++)
			if (nr_node->routes[i].neighbour==nr_neigh)
				nr_node->routes[i].hops=0;
		nr_node_unlock(nr_node);
		nr_node_put(nr_node);
		/* New link? Give it a higher rtt */
		if (nr_neigh->inp_state==NR_INP_STATE_0) {
			nr_neigh->rtt=rtt+10;
			nr_neigh->inp_state=NR_INP_STATE_RTT;
			inp3_rif_tx(nr_neigh, 1);
		}
		/* Smooth rtt */
		rtt=nr_neigh->rtt=(nr_neigh->rtt+rtt)/2;
		if (rtt>=TT_HORIZON) {
			inp3_route_neg(nr_neigh);
			nr_neigh_put(nr_neigh);
			dev_put(dev);
			return 0;
		}
		
		/* set all routes of this neighbour with new rtt */
		neg_node=kmalloc(sizeof(struct nr_node *)*MAX_RIPNEG, GFP_ATOMIC);
		if (!neg_node) {
			nr_neigh_put(nr_neigh);
			dev_put(dev);
			return 0;
		}
		spin_lock_bh(&nr_neigh_list_lock);
		spin_lock_bh(&nr_node_list_lock);
		nr_node_for_each_safe(nr_node, node, node2, &nr_node_list) {
			for (i=0; i<nr_node->count; i++) {
				if (nr_node->routes[i].neighbour == nr_neigh) {
					nr_node_lock(nr_node);
					qual=rtt2qual(nr_neigh->rtt+nr_node->routes[i].tt,
					    nr_node->routes[i].hops);
					nr_node->routes[i].quality=qual;
					oldroute=i;
					oldtt=nr_node->routes[0].neighbour->rtt+
					    nr_node->routes[0].tt;
					nr_sort_node(nr_node);
					nr_node_unlock(nr_node);
				}
			}
			if (infotype(nr_node->ltt, 
			    nr_node->routes[0].tt+nr_node->routes[0].neighbour->rtt)==-1) {
				if (neg_nodes>=MAX_RIPNEG) {
					inp3_nodes_neg(neg_node, neg_nodes, nr_neigh, &nr_neigh_list);
					neg_nodes=0;
				}
				nr_node_hold(nr_node);
				neg_node[neg_nodes]=nr_node;
				neg_nodes++;
			}
		}
		spin_unlock_bh(&nr_node_list_lock);
		if (neg_nodes) {
			inp3_nodes_neg(neg_node, neg_nodes, nr_neigh, &nr_neigh_list);
		}
		spin_unlock_bh(&nr_neigh_list_lock);
		kfree(neg_node);
		nr_neigh_put(nr_neigh);
	} else {
		struct ax25_cb *ax25s;

		nr_neigh=nr_neigh_get_dev(nr_src, ax25->ax25_dev->dev);
		if (!nr_neigh) {
			dev_put(dev);
			return 0;
		}
		if ((skbret=skb_copy(skb, GFP_ATOMIC))==NULL) {
			dev_put(dev);
			nr_neigh_put(nr_neigh);
			return 0;
		}
		skbret->data[14]--;
		dptr=skb_push(skbret, 1);
		*dptr=AX25_P_NETROM;
		ax25s=ax25_send_frame(skbret, 256, (ax25_address *)dev->dev_addr,
		    &nr_neigh->callsign, nr_neigh->digipeat, nr_neigh->dev);
		if (ax25s && nr_neigh->ax25) {
			ax25_cb_put(nr_neigh->ax25);
		}
		if (!ax25s) {
			kfree_skb(skbret);
		} else {
			nr_neigh->ax25=ax25s;
		}
		nr_neigh_put(nr_neigh);
	}
	dev_put(dev);
	return 0;
}

static void kinp3d_l3rtt(void)
{
	struct nr_neigh *nr_neigh;
	struct hlist_node *node;

	spin_lock_bh(&nr_neigh_list_lock);
	nr_neigh_for_each(nr_neigh, node, &nr_neigh_list) {
		inp3_l3rtt_tx(nr_neigh);
	}
	spin_unlock_bh(&nr_neigh_list_lock);
}

static void kinp3d_rif(void)
{
	struct nr_neigh *nr_neigh;
	struct hlist_node *node;

	kinp3d_rifcount++;
	/* Send all changed routes to the nodes, then mark them changed
	   Once in a while we send the complete list */
	spin_lock_bh(&nr_neigh_list_lock);
	nr_neigh_for_each(nr_neigh, node, &nr_neigh_list) {
		if (nr_neigh->inp_state==NR_INP_STATE_INP) {
			if (kinp3d_rifcount>=RIF_INTERVAL)
				inp3_rif_tx(nr_neigh, 1);
			else
				inp3_rif_tx(nr_neigh, 0);
		}
	}
	spin_unlock_bh(&nr_neigh_list_lock);
	if (kinp3d_rifcount>=RIF_INTERVAL) {
		kinp3d_rifcount=0;
		inp3_ltt_update(1, 0);
	} else
		inp3_ltt_update(0, 0);
}

static int kinp3d_thread(void *ptr)
{
	int l3rttcnt=0;

	kinp3d_running=1;
	
	printk(KERN_INFO "PE1RXQ INP3 for Linux. Version " INPVERSION "\n");
	do {
		if (++l3rttcnt>L3RTT_INTERVAL) {
			kinp3d_l3rtt();
			l3rttcnt=0;
		} else {
			/* Prevent rifs from messing up the rtt value */
			kinp3d_rif();
		}
		current->state=TASK_INTERRUPTIBLE;
		schedule_timeout(INP3D_INTERVAL);
	} while (!kthread_should_stop());

	info("kinp3 exiting");
	kinp3d_running=0;

	return 1;
}

void kinp3d_start(void)
{
	struct task_struct *t;
	int ret;

	t=kthread_run(kinp3d_thread, NULL, "kinp3d");
	if (IS_ERR(t)) {
		info("failed to start kinp3d");
		ret = PTR_ERR(t);
		return ret;
	}
	kinp3d_task=t;
	return;
}

void kinp3d_stop(void)
{
	int ret;

	ret=kthread_stop(kinp3d_task);
	if (!ret) {
		/* Wait 10 seconds */
		int count = 10 * HZ;
	
		while (kinp3d_running && --count) {
			current->state=TASK_INTERRUPTIBLE;
			schedule_timeout(1);
		}
		
		if (!count)
			info("failed to kill kinp3d");
	}
}


#endif /* CONFIG_NETROM_INP */
