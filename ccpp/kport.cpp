#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <map>

extern "C" int kLinktype(pcap_t *p);
/*
  pcap_dump_openでちがうファイル名でオープンしちまえば、
  かえってくるのはFILE*なので、pcap_dumpの最初の引数に
  してしまえばよい。
 */
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

using namespace std;

int
main(int argc, char *argv[])
{
  map<int, FILE*> m;
  pcap_t *handle;               /* Session handle */
  char errbuf[PCAP_ERRBUF_SIZE];        /* Error string */
  struct pcap_pkthdr header;    /* The header that pcap gives us */
  const u_char *packet;         /* The actual packet */
  struct ether_header *ep;
  struct iphdr *ip;
  struct tcphdr *tp;
  unsigned char *dp;
  int ethhdr_len, iphdr_len, tcphdr_len, data_len, counter=0;
  int tport, pivot;
  FILE* fp;
  int linktype;
  if (argc < 2) {
    exit(1);
  }
  handle = pcap_open_offline(argv[1], errbuf);
  linktype = getLinkType(argv[1]);
  if (argc ==3) {
    pivot = atoi(argv[2]);
    if (pivot <= 0) 
      pivot = 80;
  } else {
    pivot = 80;
  }
  while (1) {
    packet = pcap_next (handle, &header);
    if (!packet) {
      break;
    }
    /* Print its length */
    //fprintf (stderr, "Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    if (linktype==1) {
      ep = (struct ether_header *)packet;
      ethhdr_len = sizeof(struct ether_header);
      ip = (struct iphdr *)(packet + ethhdr_len);
    } else if (linktype==101) {
      ethhdr_len=0;
      ip = (struct iphdr *)packet;
    } else if (linktype==113) {
      ethhdr_len=16;
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
    //printf("fin -> %d\n", tp->fin);
    //printf("linktype -> %d\n", kLinktype(handle));

    tport = ntohs(tp->source);
    if (tport == pivot)
      tport = ntohs(tp->dest);
    //printf("tport -> %d\n", tport);
    fp = m[tport];
    if (fp) {
    } else {
      char fname[256]={0};
      snprintf(fname,256,"%d.pcap",tport);
      fp = (FILE*)pcap_dump_open(handle, fname);
      m[tport]=fp;
      counter ++;
      fprintf(stderr,"%d ", counter);
    }
    pcap_dump((u_char*)fp, &header,(const u_char*)packet);
  }
  fprintf(stderr,"\n");

}
/*
static int
sf_write_header(FILE *fp, int linktype, int thiszone, int snaplen)
{
        struct pcap_file_header hdr;

        hdr.magic = TCPDUMP_MAGIC;
        hdr.version_major = PCAP_VERSION_MAJOR;
        hdr.version_minor = PCAP_VERSION_MINOR;

        hdr.thiszone = thiszone;
        hdr.snaplen = snaplen;
        hdr.sigfigs = 0;
        hdr.linktype = linktype;

        if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1)
                return (-1);

        return (0);
}

static pcap_dumper_t *
pcap_setup_dump(pcap_t *p, int linktype, FILE *f, const char *fname)
{

if (sf_write_header(f, linktype, p->tzoff, p->snapshot) == -1) {
  snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "Can't write to %s: %s",
	   fname, pcap_strerror(errno));
  if (f != stdout)
    (void)fclose(f);
  return (NULL);
 }
return ((pcap_dumper_t *)f);
}

pcap_dumper_t *
pcap_dump_open(pcap_t *p, const char *fname)
{
  FILE *f;
  int linktype;

  linktype = dlt_to_linktype(p->linktype);
  if (linktype == -1) {
    snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	     "%s: link-layer type %d isn't supported in savefiles",
	     fname, linktype);
    return (NULL);
  }

  if (fname[0] == '-' && fname[1] == '\0') {
    f = stdout;
    fname = "standard output";
  } else {
#if !defined(WIN32) && !defined(MSDOS)
    f = fopen(fname, "w");
#else
    f = fopen(fname, "wb");
#endif
    if (f == NULL) {
      snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "%s: %s",
	       fname, pcap_strerror(errno));
      return (NULL);
    }
  }
  return (pcap_setup_dump(p, linktype, f, fname));
}
*/
