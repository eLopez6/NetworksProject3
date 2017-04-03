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
#define ORIGINATOR 0
#define RESPONDER 1
#define ENDPOINT_MEMBERS 2

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
#define CONNECTION_START_TS 0

#define TABLE_SIZE 47717
#define ARBITRARY_SHIFT 16
#define ARBITRARY_HASH 0x45D9F3B

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
  unsigned int payload;
  double ts;
};

// struct endpointNode {
//   double start_ts, dur;
//   unsigned int orig_ip, resp_ip;
//   unsigned int o_to_r_pkts, o_to_r_app_bytes;
//   unsigned short orig_port, resp_port, proto;
//   struct endpointNode *next;
// };

struct connectionNode{
  double start_ts, current_ts;
  unsigned short protocol;
  unsigned int endpoint_ips[ENDPOINT_MEMBERS];
  unsigned int endpoint_pkts[ENDPOINT_MEMBERS];
  unsigned int endpoint_bytes[ENDPOINT_MEMBERS];
  unsigned short endpoint_ports[ENDPOINT_MEMBERS];
  struct connectionNode *next;
};


static FILE *traceFile;
static char *traceFilePath;
static struct connectionNode *connectionTable[sizeof(struct connectionNode *) * TABLE_SIZE];

void *zmalloc(unsigned int size);
void createIP(unsigned int ip);
struct connectionNode *lookup(struct packetInfo packet);
void insertNode(struct connectionNode *nodePointer, struct packetInfo packet);
void updateNode(struct connectionNode *nodePointer, struct packetInfo packet);
int transportPacketDumping();
int printConnectionSummaries();

int main(int argc, char *argv[])
{
  int optionCount = 0;
  int option;
  short rflag, pflag, sflag, tflag;
  rflag = FALSE;
  pflag = FALSE;
  sflag = FALSE;
  tflag = FALSE;

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

  if (pflag)
    transportPacketDumping();

  if (sflag)
    printConnectionSummaries();

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


unsigned short next_packet(struct packetInfo *pkts)
{

  memset(pkts, 0x0, sizeof(struct packetInfo));
  safeFRead(&pkts->meta, sizeof(struct metaInfo), SINGLE_OBJECT, traceFile);
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
    return TRUE;

  if(pkts->meta.caplen < sizeof(struct ether_header))
    return TRUE;

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
    pkts->udpheader = (struct udphdr *)(pkts->packet + sizeof(struct ether_header) + pkts->ip_hdr_len);
    pkts->tcp_hdr_len = 0;
    if (pkts->meta.caplen < (sizeof(struct ether_header) + sizeof(struct iphdr) + UDP_HEADER_LENGTH))
    {
      pkts->udpheader = NULL;
      return TRUE;
    }
    pkts->payload = ntohs(pkts->udpheader->uh_ulen) - UDP_HEADER_LENGTH;

  }

  if (ntohs(pkts->ipheader->protocol == DECIMAL_TCP))
  {
    pkts->tcpheader = (struct tcphdr *)(pkts->packet + sizeof(struct ether_header) + pkts->ip_hdr_len);

    if (pkts->meta.caplen < (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
    {
      pkts->tcpheader = NULL;
      return TRUE;
    }

    pkts->tcp_hdr_len = pkts->tcpheader->th_off * TCP_WORD_SIZE;

    if (pkts->meta.caplen < (sizeof(struct ether_header) + sizeof(struct iphdr) + pkts->tcp_hdr_len))
    {
      pkts->tcpheader = NULL;
      return TRUE;
    }
    pkts->payload = pkts->ipheader->tot_len - pkts->ip_hdr_len - pkts->tcp_hdr_len;

  }

  return TRUE;
}

int next_usable_packet(struct packetInfo *pkts)
{
  while (next_packet(pkts))
  {
    if (pkts->ethh == NULL)
      continue;

    if (pkts->ethh->ether_type != DECIMAL_IP)
      continue;

    if (pkts->ipheader == NULL)
      continue;

    if (pkts->ipheader->protocol != DECIMAL_UDP && pkts->ipheader->protocol != DECIMAL_TCP)
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

  while (next_usable_packet(&packet))
  {
    printf("%0.6f ", packet.ts);
    if (packet.tcpheader != NULL)
    {
      createIP(ntohl(packet.ipheader->saddr));
      printf("%u ", ntohs(packet.tcpheader->th_sport));
      createIP(ntohl(packet.ipheader->daddr));
      printf("%u ", ntohs(packet.tcpheader->th_dport));

      printf("T %u %u %u\n", packet.payload, ntohl(packet.tcpheader->th_seq), ntohl(packet.tcpheader->th_ack));
    }

    if (packet.udpheader != NULL)
    {
      createIP(ntohl(packet.ipheader->saddr));
      printf("%u ", ntohs(packet.udpheader->uh_sport));
      createIP(ntohl(packet.ipheader->daddr));
      printf("%u ", ntohs(packet.udpheader->uh_dport));
      printf("U %u\n", packet.payload);
    }
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


int populateConnectionTable()
{
    struct packetInfo packet;
    struct connectionNode *nodepointer;

    while (next_usable_packet(&packet))
    {
      if ((nodepointer = lookup(packet)) == NULL)
        insertNode(nodepointer, packet);
      else
        updateNode(nodepointer, packet);
    }
    return TRUE;
}

int printConnection(struct connectionNode *connection)
{
  // printf("print connection is ran");
  printf("%0.6f %0.6f ", connection->start_ts, (connection->current_ts - connection->start_ts));
  // printf("%u %u ", connection->endpoint_ips[ORIGINATOR], connection->endpoint_ports[ORIGINATOR]);
  createIP(ntohl(connection->endpoint_ips[ORIGINATOR]));
  printf("%u ", ntohs(connection->endpoint_ports[ORIGINATOR]));
  createIP(ntohl(connection->endpoint_ips[RESPONDER]));
  printf("%u ", ntohs(connection->endpoint_ports[RESPONDER]));
  // printf("%u %u ", connection->endpoint_ips[RESPONDER], connection->endpoint_ports[RESPONDER]);

  if (connection->protocol == DECIMAL_UDP)
    printf("U ");
  else
    printf("T ");

  printf("%u %u ", connection->endpoint_pkts[ORIGINATOR], connection->endpoint_bytes[ORIGINATOR]);

  if (connection->endpoint_pkts[RESPONDER] != NO_BYTES)
  {
    printf("%u %u\n", connection->endpoint_pkts[RESPONDER], connection->endpoint_bytes[RESPONDER]);
    return TRUE;
  }
  else
  {
    printf("? ?\n");
    return TRUE;
  }

}

int printConnectionSummaries()
{
  struct connectionNode *printPointer;
  // struct connectionNode *freePointer;

  populateConnectionTable();

  for (int i = 0; i < TABLE_SIZE; i++)
    if (connectionTable[i] != NULL)
      for (printPointer = connectionTable[i]; printPointer != NULL; printPointer = printPointer->next)
      {
        // free(freePointer);   // Frees the last printed connection
        // freePointer = printPointer;
        printConnection(printPointer);
      }

  return TRUE;
}


// ############    HASHTABLE OPERATIONS     ############

unsigned int hash(struct packetInfo packet)
{
  unsigned int key, addressSum;

  addressSum = packet.ipheader->daddr + packet.ipheader->saddr + packet.ipheader->protocol;

  if (packet.ipheader->protocol == DECIMAL_UDP)
    addressSum += (packet.udpheader->uh_sport + packet.udpheader->uh_dport);
  else
    addressSum += (packet.tcpheader->th_sport + packet.tcpheader->th_dport);

  key = ((addressSum >> ARBITRARY_SHIFT) ^ addressSum) * ARBITRARY_HASH;
  return key % TABLE_SIZE;
}

struct connectionNode *lookup(struct packetInfo packet)
{
  struct connectionNode *nodepointer;

  for (nodepointer = connectionTable[hash(packet)]; nodepointer != NULL; nodepointer = nodepointer->next)
  {
    if (packet.ipheader->saddr == nodepointer->endpoint_ips[ORIGINATOR])
    {
      if (packet.ipheader->protocol == nodepointer->protocol)
        switch (nodepointer->protocol)
        {
          case DECIMAL_UDP:
            if (packet.udpheader->uh_sport == nodepointer->endpoint_ports[ORIGINATOR])
              return nodepointer;
            // else
            //   return NULL;
            break;
          case DECIMAL_TCP:
            if (packet.tcpheader->th_sport == nodepointer->endpoint_ports[ORIGINATOR])
              return nodepointer;
            // else
            //   return NULL;
            break;
        }

    }
    else if (packet.ipheader->saddr == nodepointer->endpoint_ips[RESPONDER])
    {
      if (packet.ipheader->protocol == nodepointer->protocol)
        switch (nodepointer->protocol)
        {
          case DECIMAL_UDP:
            if (packet.udpheader->uh_dport == nodepointer->endpoint_ports[RESPONDER])
              return nodepointer;
            // else
            //   return NULL;
            break;
          case DECIMAL_TCP:
            if (packet.tcpheader->th_dport == nodepointer->endpoint_ports[RESPONDER])
              return nodepointer;
            // else
            //   return NULL;
            break;
        }
    }

  }

  return NULL;
}

struct connectionNode *createNode(struct packetInfo packet)
{
  struct connectionNode *newNode = (struct connectionNode *)zmalloc(sizeof(struct connectionNode *));

  newNode->start_ts = packet.ts;
  newNode->current_ts = newNode->start_ts;
  newNode->protocol = packet.ipheader->protocol;

  newNode->endpoint_ips[ORIGINATOR] = packet.ipheader->saddr;
  newNode->endpoint_ips[RESPONDER] = packet.ipheader->daddr;

  if (newNode->protocol == DECIMAL_TCP)
  {
    newNode->endpoint_ports[ORIGINATOR] = packet.tcpheader->th_sport;
    newNode->endpoint_ports[RESPONDER] = packet.tcpheader->th_dport;
  }
  else
  {
    newNode->endpoint_ports[ORIGINATOR] = packet.udpheader->uh_sport;
    newNode->endpoint_ports[RESPONDER] = packet.udpheader->uh_dport;
  }

  newNode->endpoint_pkts[ORIGINATOR] = 1;

  newNode->endpoint_bytes[ORIGINATOR] = packet.payload;

  newNode->next = NULL;

  return newNode;
}

void insertNode(struct connectionNode *nodePointer, struct packetInfo packet)
{
  if (nodePointer == NULL)
    connectionTable[hash(packet)] = createNode(packet);

  else
    nodePointer->next = createNode(packet);

}

void updateNode(struct connectionNode *nodePointer, struct packetInfo packet)
{

  if (packet.ipheader->saddr == nodePointer->endpoint_ips[ORIGINATOR])
  {
    nodePointer->endpoint_pkts[ORIGINATOR]++;
    nodePointer->endpoint_bytes[ORIGINATOR] += packet.payload;
  }
  else
  {
    nodePointer->endpoint_pkts[RESPONDER]++;
    nodePointer->endpoint_bytes[RESPONDER] += packet.payload;
  }

  nodePointer->current_ts = packet.ts;

}
