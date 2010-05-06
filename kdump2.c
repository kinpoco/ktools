/*
  kdump		checksumをもじゅーる化
  kdump2	へっだとぼでぃとのぼりくだりをわける。
*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int
getLinkType(const char *fname)
{
  struct pcap_file_header pfh;
  int ret;
  FILE* fp;
  
  fp=fopen(fname, "r");
  if (!fp) {
    perror("fopen");
    exit(1);
  }
  ret = fread(&pfh, sizeof(pfh), 1, fp);
  if (ret!=1) {
    perror("fread");
    exit(1);
  }
  fclose(fp);
  return pfh.linktype;
}


unsigned short
tcpChecksum(struct iphdr *ip, int iphdr_len,
	    struct tcphdr *tp, int tcphdr_len,
	    unsigned char *dp, int data_len);

unsigned long
aryChecksum(unsigned short *usp, int len);
typedef union ipaddress_ {
  unsigned char seg[4];
  u_int32_t addr;
} ipaddress;
#define FNAMELEN 256

int
main (int argc, char *argv[])
{
  pcap_t *handle;		/* Session handle */
  char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
  struct pcap_pkthdr header;	/* The header that pcap gives us */
  const u_char *packet;		/* The actual packet */
  ipaddress saddr, daddr;

  struct ether_header *ep;
  struct iphdr *ip;
  struct tcphdr *tp;
  unsigned char *dp;
  int ethhdr_len, iphdr_len, tcphdr_len, data_len, counter=0;
  int first=1;
  unsigned short chksum;
  char prefix[FNAMELEN];
  int prefixLen;
  char hNameCtoS[FNAMELEN], bNameCtoS[FNAMELEN];
  char hNameStoC[FNAMELEN], bNameStoC[FNAMELEN];
  int fpHeaderCtoS,fpBodyCtoS, i;
  int fpHeaderStoC,fpBodyStoC, isBodyCS=0, isBodySC=0;
  char *hbsep, *startPrefix;
  int hsize,bsize;
  int linktype;
  int sport, dport;

  if (argc != 2) {
    fprintf(stderr,"buuuu\n");
    exit(1);
  }
  startPrefix = rindex(argv[1],'/');
  if (startPrefix==NULL) {
    startPrefix=argv[1];
  } else {
    startPrefix += 1;
  }
  handle = pcap_open_offline(argv[1], errbuf);
  linktype = getLinkType(argv[1]);
  printf("linktype:%d\n", linktype);
  strncpy(prefix, startPrefix, strlen(argv[1]));
  /*こんま以降をきる*/
  /*
  for (i = 0;i < strlen(argv[1]);i++) {
  */
  for (i = strlen(argv[1]);i > 0 ;i--) {
    if (prefix[i] == '.') {
      prefix[i] = 0;
      break;
    }
  }
  prefixLen = strlen(prefix);
  /*
    NULLもじもコピーしたいので、prefixLenに1を足している。
   */
  strncpy(hNameCtoS, prefix, prefixLen+1);
  strncpy(bNameCtoS, prefix, prefixLen+1);
  strncpy(hNameStoC, prefix, prefixLen+1);
  strncpy(bNameStoC, prefix, prefixLen+1);

  strncat(hNameCtoS, ".CHead.txt", strlen(".CHead.txt"));
  strncat(bNameCtoS, ".Cbody.txt", strlen(".Cbody.txt"));
  strncat(hNameStoC, ".SHead.txt", strlen(".SHead.txt"));
  strncat(bNameStoC, ".Sbody.txt", strlen(".Sbody.txt"));

  fprintf(stderr,"%s\n", hNameCtoS);
  fprintf(stderr,"%s\n", bNameCtoS);
  fprintf(stderr,"%s\n", hNameStoC);
  fprintf(stderr,"%s\n", bNameStoC);

  /* fprintf(stderr,"%s, %s\n", hName, bName); */
  fpHeaderCtoS = open(hNameCtoS,O_WRONLY|O_TRUNC|O_CREAT,
		      S_IRUSR | S_IWUSR);
  if (!fpHeaderCtoS) {
    perror(hNameCtoS);
  }

  fpBodyCtoS = open(bNameCtoS,O_WRONLY|O_TRUNC|O_CREAT,
		    S_IRUSR | S_IWUSR);
  if (!fpBodyCtoS) {
    perror(bNameCtoS);
  }

  fpHeaderStoC = open(hNameStoC,O_WRONLY|O_TRUNC|O_CREAT,
		      S_IRUSR | S_IWUSR);
  if (!fpHeaderStoC) {
    perror(hNameStoC);
  }

  fpBodyStoC = open(bNameStoC,O_WRONLY|O_TRUNC|O_CREAT,
		    S_IRUSR | S_IWUSR);
  if (!fpBodyStoC) {
    perror(bNameStoC);
  }



  while (1) {
    packet = pcap_next (handle, &header);
    if (!packet) {
      break;
    }
    counter ++;
    /* Print its length */
    fprintf (stderr, "Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    if (linktype==1) {
      ep = (struct ether_header *)packet;
      ethhdr_len = sizeof(struct ether_header);
      ip = (struct iphdr *)(packet + ethhdr_len);
    } else if (linktype==101) {
      ethhdr_len=0;
      ip = (struct iphdr *)packet;
    } else if (linktype==113) {
      ethhdr_len=16; //not ether...
      ip = (struct iphdr *)(packet+16);
    } else {
      printf("unsupported linktype: %d\n", linktype);
      exit(1);
    }

    /* The length of ip header is ihl * 4. */
    iphdr_len = ip->ihl*4;
    tp = (struct tcphdr *)(packet + ethhdr_len + iphdr_len);
    tcphdr_len = tp->doff*4;
    data_len = ntohs(ip->tot_len) - tcphdr_len - iphdr_len;
    if (data_len > 0) {
      dp = (unsigned char*)(packet + ethhdr_len + iphdr_len + tcphdr_len);
    } else {
      dp = NULL;
    }

    if (first) {
      saddr.addr = ip->saddr;
      daddr.addr = ip->daddr;
      sport=tp->source;
      dport=tp->dest;
      first = 0;
    }

    if (saddr.addr == ip->saddr && sport==tp->source) {
      fprintf (stderr,"C -> S\n");
    } else {
      fprintf (stderr,"S -> C\n");
    }

#ifdef KDEBUG
    printf("iphdr_len -> %d\n", iphdr_len);
    printf("total_len -> %d\n", ntohs(ip->tot_len));
    printf("seq -> %u\n", ntohl(tp->seq));
    printf("ack -> %u\n", ntohl(tp->ack_seq));
    printf("tcphdr_len = %d\ndata_len = %d\n", tcphdr_len, data_len);
#endif //KDEBUG    
  
    chksum = tcpChecksum(ip,iphdr_len,
			 tp,tcphdr_len,
			 dp,data_len);
    fprintf(stderr, " ***chksum[%4d] = 0x%04x\n", counter, chksum);

    if (data_len>0) {
      if (saddr.addr == ip->saddr && sport==tp->source) {
	/*
	  upstream
	*/
	fprintf(stderr,"upstream\n");
	hsize = bsize = 0;

	if (isBodyCS) {
	  bsize = write(fpBodyCtoS,dp,data_len);
	} else {
	  hbsep = strstr(dp, "\r\n\r\n");
	  if (hbsep == NULL) {
	    hsize = write(fpHeaderCtoS,dp,data_len);
	  } else {
	    *(hbsep+2) = 0;
	    hsize = write(fpHeaderCtoS,dp,strlen(dp));
	    bsize = write(fpBodyCtoS,hbsep+4, data_len - strlen(dp) - 2);
	    isBodyCS=1;
	  }

	}
	fprintf(stderr,"h -> %d, d -> %d\n", hsize, bsize);

      } else {
	/*
	  downstream
	 */
	hsize = bsize = 0;
	fprintf(stderr,"downstream\n");
	if (isBodySC) {
	  bsize = write(fpBodyStoC,dp,data_len);
	} else {
	  hbsep = strstr(dp, "\r\n\r\n");
	  if (hbsep == NULL) {
	    hsize = write(fpHeaderStoC,dp,data_len);
	  } else {
	    *(hbsep+2) = 0;
	    hsize = write(fpHeaderStoC,dp,strlen(dp));
	    bsize = write(fpBodyStoC,hbsep+4, data_len - strlen(dp) - 2);
	    isBodySC=1;
	  }
	}
	fprintf(stderr,"h -> %d, d -> %d\n", hsize, bsize);
      }


    }

    fprintf(stderr,"\n");
  }
  pcap_close (handle);
  close(fpHeaderStoC);
  close(fpBodyStoC);
  close(fpHeaderCtoS);
  close(fpBodyCtoS);
  return (0);
}

unsigned long
aryChecksum(unsigned short *usp, int len)
{
  unsigned long retval=0;

  if (usp == NULL || len <= 0) {
    return 0;
  }

  while (len > 1) {
    retval += htons(*usp);
    usp++;
    len -= 2;
  }
  if (len) 
    retval += ((unsigned short)(*((unsigned char *)usp)))<<8;

  return retval;
}

unsigned short
tcpChecksum(struct iphdr *ip, int iphdr_len,
	    struct tcphdr *tp, int tcphdr_len,
	    unsigned char *dp, int data_len)
{
  unsigned long cs=0;

  cs += htons(ip->saddr>>16);
  cs += htons(ip->saddr&0xffff);
  cs += htons(ip->daddr>>16);
  cs += htons(ip->daddr&0xffff);
  cs += ip->protocol;
  cs += tcphdr_len+data_len;

#ifdef KDEBUG
    printf("  >>> %x\n",htons(ip->saddr>>16));
    printf("  >>> %x\n",htons(ip->saddr&0xffff));
    printf("  >>> %x\n",htons(ip->daddr>>16));
    printf("  >>> %x\n",htons(ip->daddr&0xffff));
    printf("  >>> %x\n",htons(ip->protocol));
    printf("  >>> %x\n",htons(tcphdr_len+data_len));
#endif //KDEBUG
  cs += aryChecksum((unsigned short *)tp, tcphdr_len);
  
  if (data_len > 0) {
    cs += aryChecksum((unsigned short *)dp, data_len);
  }

  cs = (cs & 0xffff) + (cs >> 16);
  cs = (cs & 0xffff) + (cs >> 16);
  return ~((unsigned short)cs);
}
/*
struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    //The options start here.
  };


 */

/*
struct tcphdr
  {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};
*/
