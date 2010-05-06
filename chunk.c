#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

const int maxlen=1024*1024;
unsigned char tbl[256];
void one(int handle, unsigned char* warea);
void createtbl();

int
main(int argc, char *argv[])
{
  unsigned char *data;
  int i;
  off_t s;

  if (argc == 1) {
    i = fileno(stdin);
  } else if (argc == 2) {
    i = open(argv[1], O_RDONLY);
  } else {
    fprintf(stderr,"usage ... %s filename\n", argv[0]);
    exit(1);
  }

  createtbl();
  if (i == -1) {
    perror("open");
    exit(1);
  }

  data = (unsigned char *)malloc(maxlen);
  if (!data) {
    fprintf(stderr,"malloc error\n");
    exit(1);
  }
  one(i, data);
  return 0;
}

void
one(int handle, unsigned char* warea)
{
  int len, rest, i, found, chunk, finished=0;
  unsigned char *d, *hex;

  while (19) {
    len = read(handle, warea, maxlen);
    if (len==0) 
      break;
    d = warea;
    while (len) {
      hex=d;
      found=0;
      for (i = 0; i< 10; i++, hex++) {
	if (*hex == 0x0d) {
	  if (*(hex+1) == 0x0a) {
	    found = 1;
	    break;
	  }
	}
      }
      if (!found) {
	fprintf(stderr,"unknown format\n");
	exit(1);
      }
      chunk=0;
      while (d != hex) {
	/* printf("tbl[%c] = %d\n", *d, tbl[*d]); */
	chunk = chunk*16+tbl[*d];
	d++;
	len--;
      }
      if (chunk==0) {
	finished=1;
	break;
      }
      //skip 0x0a
      d++; d++;
      len--; len--;
      
      if (len > chunk) {
	write(fileno(stdout), d, chunk);
      } else {
	fprintf(stderr,"\nshort data\n");
	exit(1);
      }
      d+=chunk;
      d++; d++;
      len-=chunk;
      len--; len --;
    }

    if (finished)
      break;
    fprintf(stderr,"unsupported big data. hack, please!!!\n");
  }
}

  
  

void
createtbl()
{
  memset(tbl,0,256);
  tbl['0']=0;  tbl['1']=1;  tbl['2']=2;  tbl['3']=3;
  tbl['4']=4;  tbl['5']=5;  tbl['6']=6;  tbl['7']=7;
  tbl['8']=8;  tbl['9']=9;  tbl['a']=10;  tbl['b']=11;
  tbl['c']=12;  tbl['d']=13;  tbl['e']=14;  tbl['f']=15;
  tbl['A']=10;  tbl['B']=11;  tbl['C']=12;  tbl['D']=13;
  tbl['E']=14;  tbl['F']=15;
}
