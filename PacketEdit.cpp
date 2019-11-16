#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include "define.h"

#ifndef le32
#define le32 int32_t
#endif

#ifndef u32
#define u32 u_int32_t
#endif

#ifndef u16
#define u16 u_int16_t
#endif

#ifndef s32
#define s32 int32_t
#endif

struct pcap_file_header
{
    u32 magic;
    u16 version_major;
    u16 version_minor;
    s32 thiszone; /* gmt to local correction */
    u32 sigfigs;  /* accuracy of timL1 cache bytes userspaceestamps */
    u32 snaplen;  /* max length saved portion of each pkt */
    u32 linktype; /* data link type (LINKTYPE_*) */
} __attribute__((packed));

struct pcap_pkthdr_ts
{
    le32 hts_sec;
    le32 hts_usec;
} __attribute__((packed));

struct pcap_pkthdr
{
    struct pcap_pkthdr_ts ts; /* time stamp */
    le32 caplen;              /* length of portion present */
    le32 length;              /* length this packet (off wire) */
} __attribute__((packed));

// unsigned short udpcksum(struct ethernet *pep, int len)
// {
//     struct ip *pip = (struct ip *)pep->ep_data;
//     struct udp *pudp = (struct udp *)pip->ip_data;
//     unsigned short *sptr;
//     unsigned long ucksum;
//     int i;
//     ucksum = 0;
//     sptr = (unsigned short *)&pip->ip_src;
//     /* 2*IP_ALEN octets = IP_ALEN shorts... */
//     /* they are in net order.  */
//     for (i = 0; i < IP_ALEN; ++i)
//         ucksum += *sptr++;
//     sptr = (unsigned short *)pudp;
//     ucksum += hs2net(IPT_UDP + len);
//     if (len % 2)
//     {
//         ((char *)pudp)[len] = 0; /* pad */
//         len += 1;                /* for the following division */
//     }
//     len >>= 1; /* convert to length in shorts */
//     for (i = 0; i < len; ++i)
//         ucksum += *sptr++;
//     ucksum = (ucksum >> 16) + (ucksum & 0xffff);
//     ucksum += (ucksum >> 16);
//     return (short)(~ucksum & 0xffff);
// }

bool read_pcap_file(char *filename, u_char **buffer, long *length)
{
    FILE *infile;
    long length_read;

    infile = fopen(filename, "r");
    if (infile == NULL)
    {
        printf("File does not exist!\n");
        return false;
    }

    fseek(infile, 0L, SEEK_END);
    *length = ftell(infile);
    fseek(infile, 0L, SEEK_SET);
    *buffer = (u_char *)calloc(*length, sizeof(char));

    /* memory error */
    if (*buffer == NULL)
    {
        printf("Could not allocate %ld bytes of memory!\n", *length);
        return false;
    }

    length_read = fread(*buffer, sizeof(char), *length, infile);
    *length = length_read;
    fclose(infile);

    return true;
}

int main(int argc, char *argv[])
{
    u_char *buffer;
    long length;
    u32 packets_sent = 0;
    u32 packet_bytes = 0;
    struct pcap_pkthdr *pcap_hdr;

    if (argc != 2)
    {
        printf("Usage: ./PacketEdit <path-to-pcap>\n");
        exit(-1);
    }

    if (!read_pcap_file(argv[1], &buffer, &length))
    {
        perror("Failed to read file! ");
        exit(-1);
    }

    u_char *offset = buffer + sizeof(struct pcap_file_header);

    while (offset < buffer + length)
    {
        pcap_hdr = (struct pcap_pkthdr *)offset;
        offset += sizeof(struct pcap_pkthdr);
        print_payload(offset, pcap_hdr->caplen);
        offset += pcap_hdr->caplen;
        packets_sent++;
        packet_bytes += pcap_hdr->caplen;
    }

    printf("Done, closing everything!\n");
    printf("send pkt num %d\n", packets_sent);
    printf("\n");

    free(buffer);
    return 0;
}
