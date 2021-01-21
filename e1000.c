#include <kern/e1000.h>

#include <inc/string.h>
#include <inc/error.h>

#include <kern/pmap.h>

#define NTXDESC  16
static struct e1000_tx_desc tx_queue[NTXDESC] __attribute__ ((aligned(16)));

#define TX_PKT_BUFF_SIZE ETHERNET_PACKET_SIZE
static char tx_buffs[NTXDESC][TX_PKT_BUFF_SIZE];

#define NRXDESC  128
static struct e1000_rx_desc rx_queue[NRXDESC] __attribute__ ((aligned(16)));

#define RX_PKT_BUFF_SIZE 2048
static char rx_buffs[NRXDESC][RX_PKT_BUFF_SIZE];


int
e1000_tx_init(void) 
{
    int i;
    
    // Check if alignment requirements are satisfied  
    assert(sizeof(struct e1000_tx_desc) == 16);
    assert(((uint32_t)(&tx_queue[0]) & 0xf) == 0);
    assert(sizeof(tx_queue) % 128 == 0);
	
    // Initialize packet buffers
    memset(tx_queue, 0, sizeof(tx_queue));
    for (i = 0; i < NTXDESC; i++) 
        tx_queue[i].buff_addr = PADDR(tx_buffs[i]);
    
    // Initialize regs of transmit descriptor ring (a.k.a. transmit queue)
    E1000_REG(E1000_TDBAL) = PADDR(tx_queue); 
    E1000_REG(E1000_TDBAH) = 0;
    E1000_REG(E1000_TDLEN) = sizeof(tx_queue);
    E1000_REG(E1000_TDH)   = 0;
    E1000_REG(E1000_TDT)   = 0;
    
    // Program TCTL & TIPG
//#define E1000_TCTL           0x00400    /* Transmit Control - R/W */
//#define E1000_TCTL_EN     0x00000002    /* enable */
//#define E1000_TCTL_PSP    0x00000008    /* pad short packets */
//#define E1000_TCTL_COLD   0x003ff000    /* collision distance */
    E1000_REG(E1000_TCTL) |= E1000_TCTL_EN;
    E1000_REG(E1000_TCTL) |= E1000_TCTL_PSP;

    E1000_REG(E1000_TCTL) &= ~E1000_TCTL_COLD;
    E1000_REG(E1000_TCTL) |= 0x00040000; // TCTL.COLD: 40h

    E1000_REG(E1000_TIPG)  = 10;
    
    return 0;
}

int
e1000_rx_init(void)
{
    int i;
    memset(rx_queue, 0, sizeof(rx_queue));
    for (i = 0; i < NRXDESC; i++)
        rx_queue[i].buff_addr = PADDR(rx_buffs[i]);
    
    // configure the Receive Adress Registers with the card's 
    // own MAC address ( 52:54:00:12:34:56 ) in order to accept
    // packets addressed to the card
    E1000_REG(E1000_RAL0)  = 0x12005452;
    E1000_REG(E1000_RAH0)  = 0x80005634;   
    
    // initialize regs of receive descriptor ring
    E1000_REG(E1000_RDBAL) = PADDR(rx_queue); 
    E1000_REG(E1000_RDBAH) = 0;
    E1000_REG(E1000_RDLEN) = sizeof(rx_queue);
    E1000_REG(E1000_RDH)   = 0;
    E1000_REG(E1000_RDT)   = NRXDESC - 1;
    
    // enable receive
    E1000_REG(E1000_RCTL) |= E1000_RCTL_EN;
    
    // configure e1000 to strip the Ethernet CRC
    E1000_REG(E1000_RCTL) |= E1000_RCTL_SECRC;
     
    return 0;
}

int 
e1000_transmit(const void *data, size_t len) 
{
    uint32_t tail = E1000_REG(E1000_TDT);

    if (len > TX_PKT_BUFF_SIZE)
        return -E_PKT_TOO_LONG;	

    if ((tx_queue[tail].cmd & E1000_TXD_CMD_RS) 
        && !(tx_queue[tail].sta & E1000_TXD_STA_DD))
        return -E_TX_FULL;

    memcpy(tx_buffs[tail], data, len);
    tx_queue[tail].length = len;
    tx_queue[tail].cmd |= E1000_TXD_CMD_RS | E1000_TXD_CMD_EOP;
    tx_queue[tail].sta &= ~E1000_TXD_STA_DD;

    E1000_REG(E1000_TDT) = (tail + 1) % NTXDESC;
   
    return 0;
}

struct ethernet_h{
        //	unsigned char preamble[7];
        //	unsigned char delimiter;

    unsigned char destAddress[6];
	unsigned char srcAddress[6];
        // if value < 1500(max allowed frame size); specifies length - ver802.2
        // else value > 1536; specifies which protocol is encapsulated in the payload - Ethernet II framing
    unsigned char etherType[2];
};

struct ip_h
{
    /*need these to compute packet lengths*/
    unsigned char v_ihl; //internet header length
    unsigned char service; //Type of service - used to define the way routers handle the datagram
    unsigned char total_len[2]; //16 bits, max packet size - 2^16 - 65,536

    unsigned char identification[2]; //Used along with src address to uniquely id a datagram
    unsigned char offset[2]; // 00000xxx {Reserved = 0, Don't Fragment, Fragment} 00000000
    unsigned char ttl; //no. of hops
    unsigned char protocol; //http://bit.ly/c0xBMt list of ip protocols
    unsigned char checksum[2];
    unsigned char srcAddress[4];
    unsigned char destAddress[4];
};


struct tcp_h{
	unsigned char src_port[2];
	unsigned char dest_port[2];
	unsigned char seq_num[4];
	unsigned char ack[4];
	unsigned char offset_res_flag[2];
	unsigned char window_size[2];
	unsigned char check_sum[2];
	unsigned char urgent[2];
	unsigned char option[4];		//this char just indicates the first 4 bytes of the optional section. We me need to have a
};

struct tls_h{
	unsigned char type;
	unsigned char version[2];
	unsigned char length[2];
};


void parse(char *packet, int len){


           int  j,sz;
    cprintf("len =%d\n",len);
    /*Header Structs*/
    struct ethernet_h * ethernet;
    struct ip_h * ip;
    struct tcp_h * tcp;
        /*ethernet header memory map*/
        ethernet = (struct ethernet_h *)(packet);
        cprintf("\nMAC src:\t");
        for(j=0;j<6;j++)
        {
            cprintf("%x:", ethernet->srcAddress[j]);
        }

        cprintf("\nMAC dest:\t");
        for(j=0;j<6;j++)
        {
            cprintf("%x:", ethernet->destAddress[j]);
        }
        /*cacluate start of IP header and map to struct*/
        ip = (struct ip_h *) (packet + sizeof(struct ethernet_h));

        cprintf("\b\nIP src: \t");
        for (j=0;j<4;j++)
        {
            cprintf(" %d ", ip->srcAddress[j]);
        }
        cprintf("\nIP dest: \t");
        for (j=0;j<4;j++)
        {
            cprintf(" %d ", ip->destAddress[j]);
        }
        cprintf("\n");

 	// print src and dest port number
	tcp = (struct tcp_h *) (packet + sizeof(struct ethernet_h) + sizeof(struct ip_h)); //calulate tcp header and map to struct
	cprintf("source port- ");
	unsigned short src_port = *((unsigned short*)tcp->src_port);
	src_port = src_port>>8 | src_port<<8;
	cprintf("%d",src_port);

	cprintf("\n");
	cprintf("destination port- ");
	unsigned short dest_port = *((unsigned short*)tcp->dest_port);
	dest_port = dest_port>>8 | dest_port<<8;
	cprintf("%d",dest_port);
	cprintf("\n");
	sz = sizeof(struct ethernet_h) + sizeof(struct ip_h)+sizeof(struct tcp_h);
	
	if(sizeof(*packet) > sz)
	{
		cprintf('HTTP packet recieved')
		char *p = (char *)(packet + sz);
		for (j=sz;j<len;j++){
			cprintf("%c",*p++);
		}
	}

#ifdef more
	//calulate tls header and map to struct. This calculation  checks for the first tls message if any. It checks only for TLSv1 (using 0x0301)
	int size = header.len;
	if( size >= sizeof(struct ethernet_h) + sizeof(struct ip_h) + sizeof(struct tcp_h)+ sizeof(struct tls_h)){ 	//check if header has enough bytes for tls
		tls = (struct tls_h *) (packet + sizeof(struct ethernet_h) + sizeof(struct ip_h) + sizeof(struct tcp_h));
		unsigned char version_upper = *((unsigned char*)tls->version);
		unsigned char version_lower = *((unsigned char*)tls->version+1);
		if (version_upper == 0x03 && version_lower == 0x01){
			cprintf("TLS 1.0: Yes\n");
		}
		else{
			cprintf("TLS 1.0: No\n");
		}
		version_upper = 0;	//clearing values
		version_lower = 0;	//clearing values
	}
	else{
		cprintf("TLS 1.0: No\n");
	}
	cprintf("\n");
    }
#endif
}

int 
e1000_receive(void *buff, size_t size)
{
    uint32_t tail = E1000_REG(E1000_RDT);
    uint32_t next = (tail + 1) % NRXDESC;
    int len;

    if (!(rx_queue[next].sta & E1000_RXD_STA_DD))
        return -E_RX_EMPTY;
 
    len = rx_queue[next].length;
    if (size < len)
        return -E_PKT_TOO_LONG;

    memcpy(buff, rx_buffs[next], len);
    parse((char *)buff,len);
    rx_queue[next].sta &= ~E1000_RXD_STA_DD;

    E1000_REG(E1000_RDT) = next;
    return len;
}
