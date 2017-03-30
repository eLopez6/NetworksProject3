// Emilio Lopez, eil11
// Project3.c
// Date Created: 3/10/2017
// Code for the entire Project 3


#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>


#define ALLOWED_OPTIONS 1
#define TRUE 1
#define FALSE 0
#define NO_BYTES 0
#define SINGLE_OBJECT 1
#define MICROSECONDS_PER_SECOND 1000000
#define SINGLE_BYTE 1
#define IP_WORD_SIZE 4
#define TCP_WORD_SIZE 4
#define IP_OCTETS 4
#define OCTET_PERIODS 3
#define FIRST_OCTET 24
#define SECOND_OCTET 16
#define THIRD_OCTET 8
#define COPY_MASK 0xFF

#define MAX_ETH_PKT 1518
#define ETHERNET_HEADER_LENGTH 14
#define IP_HEADER_LENGTH 20
#define META_INFO_LENGTH 12
#define UDP_HEADER_LENGTH 8
#define TCP_HEADER_LENGTH 20
#define BOTH_ADDRESSES 12
#define DECIMAL_IP 2048
#define DECIMAL_TCP 6
#define DECIMAL_UDP 17

struct metaInfo {
  unsigned int seconds, microseconds;
  unsigned short caplen, ignored;
};

struct packetInfo {
  struct metaInfo meta;
  unsigned char packet[MAX_ETH_PKT];
  struct ether_header *ethh;
  struct iphdr *ipheader;
  struct tcphdr *tcpheader;
  struct udphdr *udpheader;
  unsigned short ip_hdr_len;
  unsigned short tcp_hdr_len;
  double ts;
};

static FILE *traceFile;
static char *traceFilePath;
static void *dummyMemory;
static struct metaInfo *metaInfo;

void *zmalloc(unsigned int size);
void createIP(unsigned int ip);
int transportPacketDumping();

int main(int argc, char *argv[])
{
  int optionCount = 0;
  int option;
  short rflag, pflag, sflag, tflag;

  while ((option = getopt(argc, argv, "r:pst ")) != -1)
  {
    switch (option)
    {
      case 'r':
        traceFilePath = optarg;
        if (traceFilePath == NULL)
        {
            printf("%s", "Missing file argument.\n");
            exit(EXIT_FAILURE);
        }
        else
        {
          rflag = TRUE;
          break;
        }

      case 'p':
        pflag = TRUE;
        optionCount++;
        break;

      case 's':
        sflag = TRUE;
        optionCount++;
        break;

      case 't':
        tflag = TRUE;
        optionCount++;
        break;

      default:
        perror("Invalid command line argument");
        exit(EXIT_FAILURE);
    }
  }

  if (optionCount > ALLOWED_OPTIONS)
  {
    perror("Only 1 command option is allowed");
    exit(EXIT_FAILURE);
  }

  /* Attempts to open the given by the -r command */

  if (rflag)
  {
    if ((traceFile = fopen(traceFilePath, "rb")) == NULL)
    {
      perror("File open failed");
      exit(EXIT_FAILURE);
    }
  }
  else
  {
    perror("No file argument. Exiting");
    exit(EXIT_FAILURE);
  }

  metaInfo = (struct metaInfo *)zmalloc(META_INFO_LENGTH);

  if (pflag)
    transportPacketDumping();

  if (sflag)
    ;

  if (tflag)
    ;


  return TRUE;
}

/* Ensures bytes are read safely from the trace */
int safeFRead(void *ptr, size_t size, size_t nobj, FILE *stream)
{
  unsigned int readSuccess;
  if ((readSuccess = fread(ptr, size, nobj, stream)) < 0)
  {
    perror("Reading failed.");
    exit(EXIT_FAILURE);
  }
  if (readSuccess == NO_BYTES)
    return NO_BYTES;
  else
    return readSuccess;
}

/* Allocates and clear memory of a parameterized size */
void *zmalloc(unsigned int size)
{
  void *p;

  if ((p = (void *)malloc(size)) == NULL)
  {
    perror("Memory allocation failed, exiting program");
    exit(EXIT_FAILURE);
  }

  memset(p, 0x0, size);
  return p;
}

/* Read a number of bytes which will not be used */
void readUnusedBytes(unsigned int bytes)
{
  dummyMemory = zmalloc(bytes);
  safeFRead(dummyMemory, bytes, SINGLE_OBJECT, traceFile);
  free(dummyMemory);
}

void convertToHostByteOrder()
{
  metaInfo->seconds = ntohl(metaInfo->seconds);
  metaInfo->microseconds = ntohl(metaInfo->microseconds);
  metaInfo->caplen = ntohs(metaInfo->caplen);
}

double combineSeconds()
{
    return (double)metaInfo->seconds +
      ((double)metaInfo->microseconds / MICROSECONDS_PER_SECOND);
}

short getPacketType()
{
  unsigned short packetType;
  readUnusedBytes(BOTH_ADDRESSES);    // the MAC addresses

  safeFRead(&packetType, sizeof(short), SINGLE_OBJECT, traceFile);
  packetType = ntohs(packetType);
  return packetType;
}

unsigned short next_packet(struct packetInfo *pkts)
{
  memset(pkts, 0x0, sizeof(struct packetInfo));
  safeFRead(&pkts->meta, sizeof(struct packetInfo), SINGLE_OBJECT, traceFile);
  pkts->meta.seconds = ntohl(pkts->meta.seconds);
  pkts->meta.microseconds = ntohl(pkts->meta.microseconds);
  pkts->meta.caplen = ntohs(pkts->meta.caplen);
  pkts->ts = pkts->meta.seconds + ((double)pkts->meta.microseconds / MICROSECONDS_PER_SECOND);

  if (pkts->meta.caplen == 0)
    return FALSE;
  if (pkts->meta.caplen > MAX_ETH_PKT){
    perror("caplen > maximum ethernet frame. exiting\n");
    exit(EXIT_FAILURE);
  }

  if (safeFRead(pkts->packet, pkts->meta.caplen, SINGLE_OBJECT, traceFile) == 0)
    return FALSE;

  if(pkts->meta.caplen < sizeof(struct ether_header))
  {
    pkts->ethh = NULL;
    return TRUE;
  }


  pkts->ethh = (struct ether_header *)pkts->packet;
  pkts->ethh->ether_type = ntohs(pkts->ethh->ether_type);

  if(pkts->meta.caplen == sizeof(struct ether_header))
    return TRUE;
  if(pkts->ethh->ether_type != DECIMAL_IP)
    return TRUE;

  pkts->ipheader = (struct iphdr *)(pkts->packet + sizeof(struct ether_header));
  pkts->ip_hdr_len = pkts->ipheader->ihl * IP_WORD_SIZE;

  if(pkts->meta.caplen < sizeof(struct ether_header) + pkts->ip_hdr_len)
  {
    pkts->ipheader = NULL;
    return TRUE;
  }

  pkts->ipheader->tot_len = ntohs(pkts->ipheader->tot_len);

  if (ntohs(pkts->ipheader->protocol == DECIMAL_UDP))
  {
    pkts->tcpheader = NULL;
    pkts->udpheader = (struct udphdr *)(pkts->packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    pkts->tcp_hdr_len = 0;
    if (pkts->meta.caplen < (sizeof(struct ether_header) + sizeof(struct iphdr) +UDP_HEADER_LENGTH))
    {
      pkts->udpheader = NULL;
      return TRUE;
    }

  }

  if (ntohs(pkts->ipheader->protocol == DECIMAL_TCP))
  {
    pkts->udpheader = NULL;
    pkts->tcpheader = (struct tcphdr *)(pkts->packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    pkts->tcp_hdr_len = pkts->tcpheader->th_off * TCP_WORD_SIZE;

    if (pkts->meta.caplen < (sizeof(struct ether_header) + sizeof(struct iphdr) + pkts->tcp_hdr_len))
    {
      pkts->tcpheader = NULL;
      return TRUE;
    }
  }

  return TRUE;
}

// int transportPacketDumping()
// {
//   double timestamp;
//   unsigned short packetType;
//   int TCPPacket = 0;
//   int UDPPacket = 0;
//
//   while (safeFRead(metaInfo, META_INFO_LENGTH, SINGLE_OBJECT, traceFile) >= 1)
//   {
//     convertToHostByteOrder();
//     timestamp = combineSeconds();
//
//
//     if (metaInfo->caplen >= ETHERNET_HEADER_LENGTH + IP_HEADER_LENGTH)
//       packetType = getPacketType();
//     else
//       continue;
//
//     struct iphdr *ipheader = (struct iphdr *)zmalloc(IP_HEADER_LENGTH);
//     struct tcphdr *tcpheader = (struct tcphdr *)zmalloc(TCP_HEADER_LENGTH);
//     struct udphdr *udpheader = (struct udphdr *)zmalloc(UDP_HEADER_LENGTH);
//
//     if (packetType == DECIMAL_IP)
//     {
//       unsigned short ipheaderLength;
//
//       safeFRead(ipheader, IP_HEADER_LENGTH, SINGLE_OBJECT, traceFile);
//
//       ipheaderLength = (ipheader->ihl * IP_WORD_SIZE);
//
//       if (ipheaderLength - IP_HEADER_LENGTH != 0)
//         readUnusedBytes(ipheaderLength - IP_HEADER_LENGTH);
//
//       if (ipheader->protocol == DECIMAL_TCP)
//       {
//         safeFRead(tcpheader, TCP_HEADER_LENGTH, SINGLE_OBJECT, traceFile);
//         if ( (tcpheader->th_off * TCP_WORD_SIZE) - TCP_HEADER_LENGTH != 0)
//           readUnusedBytes((tcpheader->th_off * TCP_WORD_SIZE) - TCP_HEADER_LENGTH);
//         TCPPacket = TRUE;
//       }
//
//       else if (ipheader->protocol == DECIMAL_UDP)
//       {
//         safeFRead(udpheader, UDP_HEADER_LENGTH, SINGLE_OBJECT, traceFile);
//         UDPPacket = TRUE;
//       }
//       else
//         continue;
//     }
//     else
//       continue;
//
//     if (UDPPacket)
//     {
//       printf("%0.6f ", timestamp);
//       createIP(ntohl(ipheader->saddr));
//       printf("%u ", ntohs(udpheader->uh_sport));
//       createIP(ntohl(ipheader->daddr));
//       printf("%u ", ntohs(udpheader->uh_dport));
//       printf("U ");
//       printf("%u\n", ntohs(udpheader->uh_ulen) - UDP_HEADER_LENGTH);
//     }
//     else if (TCPPacket)
//     {
//       printf("%0.6f ", timestamp);
//       createIP(ntohl(ipheader->saddr));
//       printf("%u ", ntohs(tcpheader->th_sport));
//       createIP(ntohl(ipheader->daddr));
//       printf("%u ", ntohs(tcpheader->th_dport));
//       printf("T ");
//       int payload = ntohs(ipheader->tot_len) - (ipheader->ihl * IP_WORD_SIZE)
//         - (tcpheader->th_off * TCP_WORD_SIZE);
//       printf("%u %u %u\n", payload, ntohl(tcpheader->th_seq), ntohl(tcpheader->th_ack));
//     }
//
//   }
//   return TRUE;
// }

int next_usable_packet(struct packetInfo *pkts)
{
  while (next_packet(pkts))
  {
    if (pkts->ethh == NULL)
      continue;
    if (ntohs(pkts->ethh->ether_type) != DECIMAL_IP)
      continue;
    if (pkts->ipheader == NULL)
      continue;
    if (pkts->ipheader->protocol != DECIMAL_UDP || pkts->ipheader->protocol != DECIMAL_TCP)
      continue;
    if (pkts->tcpheader == NULL && pkts->udpheader == NULL)
      continue;

    return TRUE;
  }
  return FALSE;
}

int transportPacketDumping()
{
  struct packetInfo packet;
  next_usable_packet(&packet);

  printf("%0.6f", packet.ts);

  if (packet.tcpheader != NULL)
  {
    createIP(ntohl(packet.ipheader->saddr));
    printf("%u ", ntohs(packet.tcpheader->th_sport));
    createIP(ntohl(packet.ipheader->daddr));
    printf("%u ", ntohs(packet.tcpheader->th_dport));
    int payload = ntohs(packet.ipheader->tot_len) - packet.ip_hdr_len - packet.tcp_hdr_len;
    printf("T %u %u %u\n", payload, ntohl(packet.tcpheader->th_seq), ntohl(packet.tcpheader->th_ack));
  }

  if (packet.udpheader != NULL)
  {
    createIP(ntohl(packet.ipheader->saddr));
    printf("%u ", ntohs(packet.udpheader->uh_sport));
    createIP(ntohl(packet.ipheader->daddr));
    printf("%u ", ntohs(packet.udpheader->uh_dport));
    printf("U %u\n", ntohs(packet.udpheader->uh_ulen) - UDP_HEADER_LENGTH);
  }

  return TRUE;
}

void createIP(unsigned int ip)
{
  int i;
  unsigned char IPAddress[IP_OCTETS];

  IPAddress[0] = (ip >> FIRST_OCTET) & COPY_MASK;
  IPAddress[1] = (ip >> SECOND_OCTET) & COPY_MASK;
  IPAddress[2] = (ip >> THIRD_OCTET) & COPY_MASK;
  IPAddress[3] = ip & COPY_MASK;

  for (i = 0; i < IP_OCTETS; i++)
  {
    printf("%u", IPAddress[i]);
    if (i != OCTET_PERIODS)
      printf(".");
    else
      printf(" ");
  }

}
