#define _GNU_SOURCE

#include <sched.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>

#include <sched.h>
#include <fcntl.h>
////================================================================================================///////////////////
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <linux/kernel-page-flags.h>
#include <stdint.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <math.h>

#include "pageset.h"

#include <vector>
#include <algorithm>
using namespace std;


int PROBECOUNT = 10000;
#define PROBEWARMUP 50
int SLOT = 30000;

#define SLICES 4
#define WAYS 16
double fraction_of_physical_memory = 0.2;

uint64_t targetphyaddr;

typedef uint64_t pointer;

#define POINTER_SIZE       (sizeof(void*) * 8)
#define ADDRESS_ALIGNMENT  6
#define MAX_XOR_BITS       7
// ----------------------------------------------

#define ETA_BUFFER 5
#define MAX_HIST_SIZE 1500
pointer getPhysicalAddr(pointer virtual_addr);
int g_pagemap_fd = -1;
size_t mapping_size;
pointer *mapping;
pointer *mapping2;
typedef struct primelist *primelist_t;
struct primelist 
{
	primelist_t probe;
	primelist_t prime;
	int data;
};
void __attribute__ ((noinline)) prime(primelist_t probeLink);
void __attribute__ ((noinline)) probe(primelist_t probeLink);
unsigned long __attribute__ ((noinline)) candi_access(void* p);
// ----------------------------------------------
size_t getPhysicalMemorySize() {
    struct sysinfo info;
    sysinfo(&info);
    return (size_t) info.totalram * (size_t) info.mem_unit;
}

// ----------------------------------------------
const char *getCPUModel() {
    static char model[64];
    char *buffer = NULL;
    size_t n, idx;
    FILE *f = fopen("/proc/cpuinfo", "r");
    while (getline(&buffer, &n, f)) {
        idx = 0;
        if (strncmp(buffer, "model name", 10) == 0) {
            while (buffer[idx] != ':')
                idx++;
            idx += 2;
            strcpy(model, &buffer[idx]);
            idx = 0;
            while (model[idx] != '\n')
                idx++;
            model[idx] = 0;
            break;
        }
    }
    fclose(f);
    return model;
}

// ----------------------------------------------
void setupMapping() {
    mapping_size = (size_t)((double)getPhysicalMemorySize() * fraction_of_physical_memory);  //RAW_DATA_SIZE; //

    if (fraction_of_physical_memory < 0.01)
        mapping_size = 2048 * 1024 * 1024u;
	  mapping_size = 2048*1024*1024u;
	//int fd = open("/dev/simple", O_RDWR); 
	//mapping = (pointer *)mmap((void *)RAW_DATA_OFFSET, RAW_DATA_SIZE, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 4096);
  /* add by lcy*/
  //The fd can be -1 because MAP_ANONYMOUS is set, the code below is equal to allocate mappingsize memory
    mapping = (pointer *)mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                   MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
                   //will not allocate physical memory here
    assert(mapping != (void *) -1);
    //printf("%s", "Initialize large memory block...\n");
    for (size_t index = 0; index < mapping_size; index += 0x40) {
        pointer *temporary = (pointer *)((uint8_t *)(mapping) + index);
        *temporary = index;
        *(temporary) = index + 1;
    }
    //printf("P:%p  %p \n", mapping, getPhysicalAddr((pointer)mapping));
    //printf("P:%p  %p \n", mapping2, getPhysicalAddr((pointer)mapping2));
    //printf("%s", " done!\n");
}

// ----------------------------------------------
size_t frameNumberFromPagemap(size_t value) {
    return value & ((1ULL << 54) - 1);
}

// ----------------------------------------------
pointer getPhysicalAddr(pointer virtual_addr) {
    pointer value;
    off_t offset = (virtual_addr / 4096) * sizeof(value);
    int got = pread(g_pagemap_fd, &value, sizeof(value), offset);
    
    assert(got == 8);

    // Check the "page present" flag.
    assert(value & (1ULL << 63));

    pointer frame_num = frameNumberFromPagemap(value);
    return (frame_num * 4096) | (virtual_addr & (4095));
}

// ----------------------------------------------
void initPagemap() {
    g_pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    assert(g_pagemap_fd >= 0);
}

void usage(char *p) {
  fprintf(stderr, "Usage: %s -a address [-m] [-q] [-p pattern] [-o outputfile] [-s slotsize] [-c probecount] [-f offsets] -n [multipliersscans]\n", p);
  exit(1);
}
 
// ----------------------------------------------
uint64_t rdtsc() 
{
    uint64_t a, d;
    asm volatile ("rdtscp" : "=a" (a), "=d" (d) : : "rcx");
    a = (d << 32) | a;
    return a;
}

void maccess(void* p)
{
  asm volatile ("movq (%0), %%rax\n"
    :
    : "c" (p)
    : "rax");
}

void flush(void* p) 
{
    asm volatile ("clflush 0(%0)\n"
      :
      : "c" (p)
      : "rax");
}

unsigned long gettime() {
  volatile unsigned long time;
  asm ("rdtsc": "=a" (time): : "%edx" );
  return time;
}

uint64_t rdtsc_begin() {
    uint64_t a, d;
    asm volatile("mfence\n\t"
                 "CPUID\n\t"
                 "RDTSCP\n\t"
                 "mov %%rdx, %0\n\t"
                 "mov %%rax, %1\n\t"
                 "mfence\n\t"
                 : "=r"(d), "=r"(a)
                 :
                 : "%rax", "%rbx", "%rcx", "%rdx");
    a = (d << 32) | a;
    return a;
}

uint64_t rdtsc_end() {
    uint64_t a, d;
    asm volatile("mfence\n\t"
                 "RDTSCP\n\t"
                 "mov %%rdx, %0\n\t"
                 "mov %%rax, %1\n\t"
                 "CPUID\n\t"
                 "mfence\n\t"
                 : "=r"(d), "=r"(a)
                 :
                 : "%rax", "%rbx", "%rcx", "%rdx");
    a = (d << 32) | a;
    return a;
}


/*question: the timestamp counter is 64 bits, only considering the lower 32 bits
 neglects the overflow in the lower part.*/
/* Answer: As long as the delay is less than 2^32 we can use simple modular arithmetic on 32 
 * bit integers. This avoids the overhead of looking at the MSB 32 bits */

bool test_evict(pointer x, primelist_t prime_le, primelist_t probe_le) {
  int vec_count = 0;
  //test 10 times
  for (int i=0; i<10; ++i){
    int first = candi_access((void*)x);
    int second = candi_access((void*)x);
    for (int i=0;i<1000;++i)
    {
      prime(prime_le);
      prime(prime_le);
      probe(probe_le);
    }
    int third = candi_access((void*)x);
    if (third > 48) vec_count++;

  }
  return (vec_count > 8);

}


void delay(uint32_t start, uint32_t cycles) {
    /*spinning  for N cycles*/
    
    if (start == 0)
        start = gettime();
    while (gettime() - start < cycles)
        ;
}

size_t getslicesmapping(uint64_t phys_addr)  
{
	//static const size_t h1[] = { 17, 18, 20, 22, 24, 25, 26, 27, 28, 30, 32 };
	//static const size_t h0[] = { 18, 19, 21, 23, 25, 27, 29, 30, 31, 32};  // likely to be correct, at least compared with the others
	
  // Haswell
	//static const size_t h0[] = { 17, 18, 20, 22, 24, 25, 26, 27, 28, 30, 32 };
	//static const size_t h1[] = { 19, 22, 23, 26, 27, 30, 31 };
	//static const size_t h2[] = { 17, 20, 21, 24, 27, 28, 29, 30 };  // hyperthreading is on
	
  // generated by performance counter
  static const size_t h0[] = { 6, 10, 12, 14, 16, 17, 18, 20, 22, 24, 25, 26, 27, 28, 30, 32, 33};
  static const size_t h1[] = { 7, 11, 13, 15, 17, 19, 20, 21, 22, 23, 24, 26, 28, 29, 31, 33, 34};
  //static const size_t h2[] = { 10, 11, 13, 16, 17, 18, 19, 20, 21, 22, 27, 28, 30, 31, 32, 33};
	//static const size_t h0[] = { 17, 19, 20, 21, 22, 23, 24, 26, 28, 29, 31 };
	//static const size_t h1[] = { 18, 19, 21, 23, 25, 27, 29, 30, 31 };
  // from okaland 24
	static const size_t h2[] = { 9, 12, 16, 17, 19, 21, 22, 23, 25, 26, 27, 29, 31, 32, 33, 34};
	//static const size_t h0[] = { 6, 10, 12, 14, 16, 17, 18, 20, 22, 24, 25, 26, 27, 28, 30, 32 };
	//static const size_t h1[] = { 7, 11, 13, 15, 17, 19, 20, 21, 22, 23, 24, 26, 28, 29, 31, 33, 34 };
	//static const size_t h0[] = { 6, 10, 12, 14, 16, 17, 18, 20, 22, 24, 25, 26, 27, 28, 30, 32, 33 };
	//static const size_t h1[] = { 6, 7, 10, 11, 12, 13, 14, 15, 16, 18, 19, 21, 23, 25, 27, 29, 30, 31, 32, 34 };

	size_t count = sizeof(h0) / sizeof(h0[0]);
	size_t hash = 0;
	for (size_t i = 0; i < count; i++) 
	{
		hash ^= (phys_addr >> h0[i]) & 1;
	}
	
	//return hash;
	count = sizeof(h1) / sizeof(h1[0]);
	size_t hash1 = 0;
	for (size_t i = 0; i < count; i++) 
	{
		hash1 ^= (phys_addr >> h1[i]) & 1;
	}
	return (hash1 << 1) | hash;
	
  count = sizeof(h2) / sizeof(h2[0]);
	size_t hash2 = 0;
	for (size_t i = 0; i < count; i++) 
	{
		hash2 ^= (phys_addr >> h2[i]) & 1;
	}
	
	return (hash2 << 2) | (hash1 << 1) | hash;
  
  
  
  

}


size_t getcacheset(uint64_t phys_addr)
{
	return ( (phys_addr >> 6) & 0x1fff);   // bit 6~18 for a cache set
}

primelist_t initList() 
{
	return NULL;
}

int putout(primelist_t &list, uint64_t addr)
{
  int found = 0;
  if (list == NULL) return -1;
  primelist_t cur = list;
  if(addr == (uint64_t)cur) {
    primelist_t next = cur->prime;
    list = next;
    found = 1;
    return found;
  }
  while (cur->prime!=NULL){
    if(addr == (uint64_t)cur) {
      primelist_t former = cur->probe;
      primelist_t next = cur->prime;
      former->prime = next;
      next->probe = former;
      found = 1;
    }
    cur = cur->prime;
  }
  if (found == 0) {
    primelist_t former = cur->probe;
    former->prime = NULL;
    found = 1;
  }
  return found;

}
void insert(primelist_t &list, uint64_t addr)
{
	if(list == NULL)
	{
		//printf("inserting first element..\n");
		primelist_t cur = (primelist_t)addr;
		cur->probe = NULL;
		cur->prime = NULL;
		cur->data = 0;
		
		list = cur;
		
		//printf("inserted first element..\n");
		return;
	}
	
	primelist_t last = list;
	primelist_t cur = (primelist_t)addr;
	
	while(last->probe != NULL)
		 last = last->probe;
    cur->prime = last;
    last->probe = cur;
    cur->probe = NULL;
    cur->data = 0;
    
    list = cur;
    //printf("inserted: %p, previous addr: %p\n", addr, cur->prime);
}

void printlist(primelist_t le) {
	primelist_t tmp = le;
	while (tmp) 
	{
		printf("P:%p  %p  (%p)\n", tmp, getPhysicalAddr((pointer)tmp), syscall(323, tmp));
		tmp = tmp->prime;
	}
 
	putchar ('\n');
}

void accesslist(primelist_t le) {
	primelist_t tmp = le;
  unsigned long start, end, atime;
  int counter = 0;
  //while(tmp->prime) {
    //flush(tmp);
    //tmp = tmp->prime;
  //}
  //tmp = tmp->probe;

  while (tmp) 
	{
		//printf("P:%p  %p  (%p)\n", tmp, getPhysicalAddr((pointer)tmp), syscall(323, tmp));
    start = rdtsc_begin();
    maccess(tmp);
    end = rdtsc_end();
    atime = end -start;
    //printf("access time is %ld\n",atime);
    tmp = tmp->prime;
	}
  
	putchar ('\n');
}

void printprobelist(primelist_t le) {
	primelist_t tmp = le;
	while (tmp) 
	{
		printf("P:%p  %p  (%p)\n", tmp, getPhysicalAddr((pointer)tmp), syscall(323, tmp));
		tmp = tmp->probe;
	}
 
	putchar ('\n');
}

/*traversing the prime list until the NULL pointer*/
void __attribute__ ((noinline)) prime(primelist_t probeLink) {
  asm __volatile__ (
    "L4:			\n"
//    "  incl 16(%0)               \n"
    "  mov 8(%0), %0		\n"
    "  test %0, %0		\n"
    "  jne L4			\n"
  : : "r" (probeLink) : );
}


/*traversing the prime list until the NULL pointer*/
void __attribute__ ((noinline)) probe(primelist_t probeLink) {
  asm __volatile__ (
    "L5:			\n"
 //   "  incl 16(%0)               \n"
    "  mov (%0), %0		\n"
    "  test %0, %0		\n"
    "  jne L5			\n"
  : : "r" (probeLink) : );
}

/*assuming 200 cycle is memory latency? thus the cache line is evicted 
 from L3 cache? */
/*traverse the probe list until NULL pointer, and return the number of entries that 
 are contained in level 2 cache*/
int __attribute__ ((noinline)) probe_timelist(primelist_t le) {
  volatile int l = 0;
  
  asm __volatile__ (
    "  xorl %%edi, %%edi	\n"
    "L2:			\n"
    "  mfence                   \n"
    "  lfence                   \n"
    "  rdtsc			\n"
    "  movl %%eax, %%esi	\n"
    "  mov (%1),%1		\n"
    "  rdtscp			\n"
    "  subl %%esi, %%eax	\n"
    "  cmpl $100, %%eax		\n"
    "  jle L3			\n"
    "  incl %%edi		\n"
    "L3:			\n"
    "  test %1, %1		\n"
    "  jne L2			\n"
    "  movl %%edi, %0		\n"
      :"=a" (l)
      :"b" (le)
      :"%edx","%esi", "%rdi", "%ecx");
  return l;
}

unsigned long __attribute__ ((noinline)) warmup_llc(primelist_t le) {
  volatile int l = 0;
  
  asm __volatile__ (
    "  xorl %%edi, %%edi	\n"
    //"  xorq %%rdx, %%rdx	\n"
    "  mfence                   \n"
    "  lfence                   \n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov 8(%1),%1		\n"
    //probe again
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  mov $0,16(%1)		\n"
    "  mov (%1),%1		\n"
    "  lfence         \n"
    //"  incl %%edi		\n"
    //"  cmpl $12, %%edi		\n" //jump if edi < first num
    //"  jle LL			\n"
    "  movl %%edi, %0		\n"
      :"=a" (l)
      :"b" (le)
      :"%edx","%esi", "%rdi", "%ecx");
  return l;
}

unsigned long __attribute__ ((noinline)) warmup(primelist_t le) {
  volatile int l = 0;
  
  asm __volatile__ (
    "  xorl %%edi, %%edi	\n"
    //"  xorq %%rdx, %%rdx	\n"
    "  mfence                   \n"
    "  lfence                   \n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    //probe again
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  lfence         \n"
    //"  incl %%edi		\n"
    //"  cmpl $12, %%edi		\n" //jump if edi < first num
    //"  jle LL			\n"
    "  movl %%edi, %0		\n"
      :"=a" (l)
      :"b" (le)
      :"%edx","%esi", "%rdi", "%ecx");
  return l;
}

unsigned long __attribute__ ((noinline)) access_time(primelist_t le) {
  volatile int l = 0;
    asm __volatile__ (
    "  xorl %%edi, %%edi	\n"
    //"  xorq %%rdx, %%rdx	\n"
    "  mfence                   \n"
    "  lfence                   \n"
    "  rdtscp			\n"
    "  movl %%eax, %%esi	\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  lfence         \n"
    "  rdtscp			\n"
    "  subl %%esi, %%eax	\n"
    "  addl %%eax, %%edi  \n"
    //"  incl %%edi		\n"
    //"  cmpl $12, %%edi		\n" //jump if edi < first num
    //"  jle LL			\n"
    "  movl %%edi, %0		\n"
      :"=a" (l)
      :"b" (le)
      :"%edx","%esi", "%rdi", "%ecx");
  
  return l;
}

unsigned long __attribute__ ((noinline)) candi_access(void* p) {
  volatile int l = 0;
    asm __volatile__ (
    "  xorl %%edi, %%edi	\n"
    //"  xorq %%rdx, %%rdx	\n"
    "  mfence                   \n"
    "  lfence                   \n"
    "  rdtscp			\n"
    "  movl %%eax, %%esi	\n"
    "  movq (%1), %1		\n"
    "  lfence         \n"
    "  rdtscp			\n"
    "  subl %%esi, %%eax	\n"
    "  addl %%eax, %%edi  \n"
    //"  incl %%edi		\n"
    //"  cmpl $12, %%edi		\n" //jump if edi < first num
    //"  jle LL			\n"
    "  movl %%edi, %0		\n"
      :"=a" (l)
      :"b" (p)
      :"%edx","%esi", "%rdi", "%ecx");
  
  return l;
}

void doProbes(primelist_t primeList, primelist_t probeList, char *buf, int count, int warmup, int slot) 
{
    
    /*sequence: probe, prime, prime, delay for N cycles*/
    
    for (int i = -warmup; i < count; i++) 
    {
        uint32_t slotstart = gettime();
        /*question: does the number has too be smaller than a char? */
	/* answer: probe_timelist returns the number of ways that were brought in from memory.  On Intel the maximum value is 16 */
        char t = probe_timelist(probeList);
        printf("access pattern is %d\n",t);
        if (i >= 0)
            buf[i] = t;
        prime(primeList);
        prime(primeList);
        delay(slotstart, SLOT);
    }
}

int match1(char *buf, char *pattern) {
  int w = 0;
  while (*pattern) {
    w += (*pattern == *buf);
    pattern++;
    buf++;
  }
  return w;
}



int match(char *buf, int len, char *pattern) {
  int patternlen = strlen(pattern);

  int rv = 0;
  for (int i = 0; i < len; i++)
    buf[i] = (buf[i]==0) ? '0' : '1';

    /*finding a pattern in a flow, return number of matching possibilities*/
  for (int i = 0; i < len - patternlen; i++) {
    int w = match1(buf + i, pattern);
    if (w >= patternlen-3) 
      rv++;
  }
  return rv;
}

// ----------------------------------------------
int main(int c, char **v) {
    int ch;
	int mulComponents = 0;
	char *outname = NULL;
	FILE *out=stdout;
	long probeAddress = 0;
	char *pattern = NULL;
	int quick = 0;
	int offsets[64];
	int noffsets = 64;
	int mulscans = 8;
    
    while ((ch = getopt(c, v, "n:f:a:c:p:o:qs:m")) != -1) {
    switch(ch) {
      case 'a': targetphyaddr = strtol(optarg, NULL, 0); break;
      case 'c': PROBECOUNT = strtol(optarg, NULL, 0); break;
      case 'p': pattern = optarg; break;
      case 'o': outname = optarg; break;
      case 'q': quick = 1; break;
      case 's': SLOT = strtol(optarg, NULL, 0); break;
      case 'm': mulComponents = quick = 1; break;
      case 'n': mulscans = strtol(optarg, NULL, 0); break;
      case 'f': {
	  char *tok;
	  noffsets = 0;
	  while ((tok = strsep(&optarg, ",")) != NULL) {
	    //optarg = NULL;
	    offsets[noffsets++] = strtol(tok, NULL, 16) ;
	    if (noffsets == sizeof(offsets)/sizeof(offsets[0]))
	      break;
	  }
	}
	break;
      case '?':
      default: usage(*v);
    }
  }

	/* pin the process to core 2 */
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(2, &mask);
  //printf("Process id: %d\n", getpid());
	while(sched_setaffinity(0, sizeof(cpu_set_t), &mask)<0)
		perror("sched_setaffinity"); 

  
	if (outname != NULL)
      out = fopen(outname, "w");
      
    //printf("CPU: %s\n", getCPUModel());
    //printf("Memory percentage: %f\n", fraction_of_physical_memory);

    srand(time(NULL));
    initPagemap();
    setupMapping();
    //printf("Mapping has %zu MB\n", mapping_size / 1024 / 1024);
    
    //size_t slice = getslicesmapping(targetphyaddr);
	//size_t set = getcacheset(targetphyaddr);
	
//	size_t slice2 = getslicesmapping(targetphyaddr + 0x30);
//	size_t set2 = getcacheset(targetphyaddr + 0x30);
	
	//printf("P:%p -> %zu, %zu\n", targetphyaddr, slice, set);
	  size_t slice = 1;
	  size_t set = 0;
    //printf("slice: %zu, set: %zu\n", slice, set);
	primelist_t primeprobelist = initList();
//	primelist_t primeprobelist2 = initList();
	//printf("init prime list finished.\n");
	int count = 0;
	
	vector<uint64_t> myvector;
	bool is_cand_sel = 0;
  pointer candidate = 0;
	for (size_t i = 0; i < mapping_size; i += 64)
	{
		//printf("i: %lld\n",i);
    pointer phy_addr = getPhysicalAddr((uint64_t)((uint8_t *)mapping + i));
    //if( getPhysicalAddr((uint64_t)((uint8_t *)mapping + i)) >> 32 ) continue;
		if ( (getslicesmapping(phy_addr) == slice) &&
					 (getcacheset(phy_addr) == set)  )   //  
		{ 
      if (count == 7) {
        candidate = (uint64_t)((uint8_t *)mapping + i);
        //printf("P: %p\n",candidate);
        count++;
        is_cand_sel = 1;
      }
      else {
        myvector.push_back((uint64_t)((uint8_t *)mapping + i));
			  count++;
      }
      
      //printf("P: %p, set: %ld\n",phy_addr, getcacheset(phy_addr));
			//insert(primeprobelist, (uint64_t)(mapping + i));
			
			
			if(count >= 64) break;
		}
	}
  
	random_shuffle ( myvector.begin(), myvector.end() );
	
	count = 0;
	for (vector<uint64_t>::iterator it=myvector.begin(); it!=myvector.end() && count < 13; ++it, ++count)
	{
		insert(primeprobelist, *it);
	}
	//sleep(1);
	primelist_t primeLists =  primeprobelist;
	primelist_t probeLists =  primeprobelist;
	
//	primelist_t primeLists2 =  primeprobelist2;
//	primelist_t probeLists2 =  primeprobelist2;
	
	while(probeLists->prime != NULL)
		probeLists = probeLists->prime;
//	while(probeLists2->prime != NULL)
//		probeLists2 = probeLists2->prime;
	
	//printf("Gen prime list finished.\n");
	//printlist(primeprobelist);
	//printprobelist(probeLists);
  //printf("Starting\n");
  //printf("warmup here!\n");
  //for(int i=0;i<400;++i) {
    //warmup_llc(primeprobelist);
  //}
  int first = 0, second = 0, third = 0;
  first = candi_access((void*)candidate);
  second = candi_access((void*)candidate);
  
  for(int i=0;i<10000;++i) {
     prime(primeLists);
     prime(primeLists);
     probe(probeLists);
  }
  
  //flush((void*)candidate);
  //printf("warmup finished!\n");
	//int time_cost = access_time(primeprobelist);
  //int time_cost = access_time(primeprobelist);
  third = candi_access((void*)candidate);
  //printf("The first access time is %d\n",first);
  //printf("The second access time is %d\n",second);
  //printf("The third access time is %d\n",third);
  bool verified = (third > 100);
  printf("%d",third);
	//printf("Print primelist finished.\n");
  //sleep(3);
  //unsigned long start, end, cost_time[12];
  //primelist_t ptr = primeprobelist;
  //printf("Process id: %d\n", getpid());
  //sleep(200);

  
  

	// warmup
  /*

	
	char l[PROBECOUNT];
	
	//question: why colour * 40, generating randomizd probing sequence? 
    // Answer: Just to make sure we have enough probes.  With recent changes we need less than 40. 
    for (int c = 0; c < 50; c++) {
      
      //probe + prime on coloured lists, and print the number of evicted cache lines
      doProbes(primeLists, probeLists, l, PROBECOUNT, PROBEWARMUP, SLOT);
      
      for (int i = 0; i < PROBECOUNT; i++)
      {
      //	l[i] /= 2;
	  	fputc(l[i] + (l[i] < 10 ? '0' : ('a'-10)), out);
	  }
      fputc('\n', out);
      
      if (pattern != NULL) {
        //comparing the probing pattern with the target pattern, number of evicted cache lines in the probe list
          int score = match(l, PROBECOUNT, pattern);
          if (score * 10000 > 300 * PROBECOUNT) {
              printf("line score %d\n", score);
              
              if (quick) {
                  //confirming the pattern by having 10 more iterations
                  int x = 0;
                  for (int i = 0; i < 10; i++) {
                      doProbes(primeprobelist, primeprobelist, l, PROBECOUNT, PROBEWARMUP, SLOT);
                      if (match(l, PROBECOUNT, pattern) * 10000 >300 * PROBECOUNT) {
                          x++;
                          printf("Round %d passed\n", i);
                      } else {
                          printf("Round %d failed\n", i);
                      }
                  }
              }
          }
      }
    }
  */
	
	// start Probe
    /*using a small array, avoiding cache footprints? */
    /* Using smaller elements reduces the chance of using conflicting lines at the cost of a larger interference
     * when a conflict arrises.  */
/*    int mulcolour = -1;
 //     return 0;
 //   printf("priming..\n");
    while(1)
    {
    	//probe(probeLists);
   		prime(primeLists);
   		prime(primeLists);
   		//probe(probeLists2);
 //  		prime(primeLists2);
 //  		prime(primeLists2);
    }*/	
    return 0;

}

	/*
	//question: why colour * 40, generating randomizd probing sequence? 
    // Answer: Just to make sure we have enough probes.  With recent changes we need less than 40. 
    for (int c = 0; c < 50; c++) {
      
      //probe + prime on coloured lists, and print the number of evicted cache lines
      doProbes(primeprobelist, primeprobelist, l, PROBECOUNT, PROBEWARMUP, SLOT);
      
      for (int i = 0; i < PROBECOUNT; i++)
	  fputc(l[i] + (l[i] < 10 ? '0' : ('a'-10)), out);
      fputc('\n', out);
      
      if (pattern != NULL) {
        //comparing the probing pattern with the target pattern, number of evicted cache lines in the probe list
          int score = match(l, PROBECOUNT, pattern);
          if (score * 10000 > 300 * PROBECOUNT) {
              printf("line score %d\n", score);
              
              if (quick) {
                  //confirming the pattern by having 10 more iterations
                  int x = 0;
                  for (int i = 0; i < 10; i++) {
                      doProbes(primeprobelist, primeprobelist, l, PROBECOUNT, PROBEWARMUP, SLOT);
                      if (match(l, PROBECOUNT, pattern) * 10000 >300 * PROBECOUNT) {
                          x++;
                          printf("Round %d passed\n", i);
                      } else {
                          printf("Round %d failed\n", i);
                      }
                  }
              }
          }
      }
    }
    
    */


