#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>
int
main(int argc, char *argv[])
{
  int f;
  size_t siz, aftsiz=0;
  unsigned char *b, *a, *pa;

  if (argc != 2) {
    fprintf(stderr,"usage ... %s filename\n", argv[1]);
    exit(1);
  }
  f = open(argv[1], O_RDONLY);
  if (f == -1) {
    perror("open");
    exit(1);
  }
  siz = lseek(f, 0, SEEK_END);

  fprintf(stderr,"siz = %u\n", siz);
  b = (unsigned char*)malloc(siz);
  if (!b) {
    fprintf(stderr,"alloc error\n");
    exit(1);
  }
  pa = a = (unsigned char*)malloc(siz);
  if (!a) {
    fprintf(stderr,"alloc error\n");
    exit(1);
  }

  lseek(f, 0, SEEK_SET);
  if (read(f, b, siz) != siz) {
    fprintf(stderr,"something happened during read()\n");
    exit(1);
  }

  while (siz) {
    if (*b == 0x0d) {
      b++;
      siz--;
      if (*b == 0x0a) {
	*a = 0x0a;
	a++;
	b++;
	siz --;
	continue;
      } else {
	*a = 0x0d;
	a++;
	continue;
      }
    } else {
      *a = *b;
      a++;
      b++;
      siz--;
    }
  }

  siz = a - pa;
  fprintf(stderr,"siz = %d\n", siz);
  write(fileno(stdout), pa, a - pa);
  return 0;
}

