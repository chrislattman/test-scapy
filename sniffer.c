#define _GNU_SOURCE // needed for memmem
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

#define IPV4_ADDR_LEN 16
#define ETHER_ADDR_LEN 6

/* BSD-specific loopback Ethernet header */
struct sniff_loopback_bsd {
    u_int prot; /* Protocol type */
};

/* Ethernet header (also defined in net/ethernet.h as struct ether_header) */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* Destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* Source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header (also defined in netinet/ip.h as struct ip) */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                /* reserved fragment flag */
#define IP_DF 0x4000                /* don't fragment flag */
#define IP_MF 0x2000                /* more fragments flag */
#define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};
#define IP_HL(ip)                   (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                    (((ip)->ip_vhl) >> 4)

/* TCP header (also defined in netinet/tcp.h as struct tcphdr) */
struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    u_int   th_seq;     /* sequence number */
    u_int   th_ack;     /* acknowledgement number */
    u_char  th_offx2;   /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short  th_win;    /* window */
    u_short  th_sum;    /* checksum */
    u_short  th_urp;    /* urgent pointer */
};

static int link_layer_header_type;

static struct pcap_pkthdr *stored_packet_header = NULL;
static unsigned char *stored_packet = NULL;
static unsigned char **payloads = NULL;
static unsigned int *payload_lengths = NULL;
static unsigned int payloads_count = 0;
static char *decoded_payload = NULL;
static int encrypted;
static int file_upload;

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    unsigned int size_ethernet_hdr, size_ip_hdr, size_tcp_hdr, payload_offset, payload_length;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const unsigned char *u_payload;
    const char *payload;

    if (link_layer_header_type == DLT_NULL) {
        size_ethernet_hdr = sizeof(struct sniff_loopback_bsd);
    } else { // link_layer_header_type == DLT_EN10MB
        size_ethernet_hdr = sizeof(struct sniff_ethernet);
    }
    ip = (struct sniff_ip*)(packet + size_ethernet_hdr);
    size_ip_hdr = IP_HL(ip) * 4;
    tcp = (struct sniff_tcp*)(packet + size_ethernet_hdr + size_ip_hdr);
    size_tcp_hdr = TH_OFF(tcp) * 4;
    payload_offset = size_ethernet_hdr + size_ip_hdr + size_tcp_hdr;
    payload_length = header->caplen - payload_offset;

    if (encrypted || file_upload) {
        u_payload = (unsigned char *)(packet + payload_offset);
        payloads[payloads_count] = malloc(payload_length);
        if (payloads[payloads_count] == NULL) {
            fprintf(stderr, "malloc: %s\n", strerror(errno));
        } else {
            memcpy(payloads[payloads_count], u_payload, payload_length);
            payload_lengths[payloads_count] = payload_length;
            ++payloads_count;
        }
    } else {
        payload = (char *)(packet + payload_offset);
        decoded_payload = malloc(payload_length);
        stored_packet_header = malloc(sizeof(struct pcap_pkthdr));
        stored_packet = malloc(header->caplen);
        if (decoded_payload == NULL || stored_packet_header == NULL || stored_packet == NULL) {
            fprintf(stderr, "malloc: %s\n", strerror(errno));
        } else {
            strncpy(decoded_payload, payload, payload_length);
            memcpy(stored_packet_header, header, sizeof(struct pcap_pkthdr));
            memcpy(stored_packet, packet, header->caplen);
        }
    }
}

static void sniff_packets(void)
{
    char errbuf[PCAP_ERRBUF_SIZE], ip_addr[IPV4_ADDR_LEN], *loopback_iface,
        *curr, *body, *username, *password, *request_str, *request_str_copy = NULL,
        *boundary_start, *boundary_end, *boundary = NULL, *username_end,
        *password_end, *username_copy = NULL, *password_copy = NULL,
        *username_stripped = NULL, *password_stripped = NULL;
    const char *filter_exp, *payload_0;
    const unsigned char *packet_0;
    pcap_if_t *ifaces, *iface;
    struct pcap_addr *pcap_address;
    int count, error = 1, compiled = 0, status;
    pcap_t *handle = NULL, *reader = NULL;
    bpf_u_int32 net, mask;
    struct bpf_program fp;
    ptrdiff_t username_length, boundary_length, password_length, i, stripped_i;
    unsigned int index, second_payload_index, size_ethernet, size_ip, size_tcp;
    unsigned char *payload, *content_type, *second_content_type;
    pcap_dumper_t *dumper;
    struct pcap_pkthdr *header;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;

    if (pcap_findalldevs(&ifaces, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    for (iface = ifaces; iface != NULL; iface = iface->next) {
        pcap_address = iface->addresses->next;
        if (pcap_address != NULL && pcap_address->addr->sa_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *) pcap_address->addr)->sin_addr,
                ip_addr, IPV4_ADDR_LEN);
            if (strcmp(ip_addr, "127.0.0.1") == 0) {
                loopback_iface = malloc(strlen(iface->name) + 1);
                if (loopback_iface == NULL) {
                    fprintf(stderr, "malloc: %s\n", strerror(errno));
                    pcap_freealldevs(ifaces);
                    exit(1);
                }
                strcpy(loopback_iface, iface->name);
                break;
            }
        }
    }
    pcap_freealldevs(ifaces);

    if (file_upload) {
#ifdef __linux__
        count = 4;
#else
        count = 2;
#endif
    } else {
        count = 1;
    }
    payloads = malloc(count * sizeof(char *));
    payload_lengths = malloc(count * sizeof(unsigned int));
    if (payloads == NULL || payload_lengths == NULL) {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        goto cleanup;
    }

    if (pcap_lookupnet(loopback_iface, &net, &mask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        goto cleanup;
    }
    handle = pcap_open_live(loopback_iface, 262144, 0, 5000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        goto cleanup;
    }
    link_layer_header_type = pcap_datalink(handle);

    /*
     * The destination host, which should be localhost, can be identified
     * with dst host (source host is src host). You can inspect the TCP
     * flags in tcp[tcpflags] which are bitwise ORed with each other, e.g.
     * tcp[tcpflags] & 0x08 equals 1 if the TCP PSH flag is set.
     *
     * Advanced: you can send raw IP packets or Ethernet frames with
     * pcap_inject(): https://www.tcpdump.org/manpages/pcap_inject.3pcap.html
     */
    filter_exp = "tcp dst port 5000 and "
        "(((ip[2:2] - ((ip[0] & 0xf) << 2)) - ((tcp[12] & 0xf0) >> 2)) != 0)";
    if (pcap_compile(handle, &fp, filter_exp, 0, mask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
        goto cleanup;
    }
    compiled = 1;
    if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
        goto cleanup;
    }
    // TODO: create another thread that calls pcap_get_selectable_fd() and poll
    // fd for packet using select, then call pcap_breakloop() when packet is
    // received. This allows for a timeout of 0 in pcap_open_live()
    if (pcap_loop(handle, count, got_packet, NULL) == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(handle));
        goto cleanup;
    }

    if (!encrypted) {
        if (file_upload) {
            payload = payloads[0];
            if (memmem(payload, payload_lengths[0],
                    (unsigned char *) "Content-Disposition",
                    strlen("Content-Disposition")) == NULL) {
#ifdef __linux__
                second_payload_index = 2;
#else
                second_payload_index = 1;
#endif
                content_type = memmem(payloads[second_payload_index],
                    payload_lengths[second_payload_index],
                    (unsigned char *) "Content-Type", strlen("Content-Type"));
                content_type[0] = '\0';
                request_str_copy = malloc(payload_lengths[0] + strlen(
                    (char *) payloads[second_payload_index]) + 1);
                if (request_str_copy == NULL) {
                    fprintf(stderr, "malloc: %s\n", strerror(errno));
                    goto cleanup;
                }
                memcpy(request_str_copy, payload, payload_lengths[0]);
                strcpy(request_str_copy + payload_lengths[0],
                    (char *) payloads[second_payload_index]);
                request_str = request_str_copy;
            } else {
                content_type = memmem(payload, payload_lengths[0],
                    (unsigned char *) "Content-Type", strlen("Content-Type"));
                content_type += strlen("Content-Type: multipart/form-data");
                second_content_type = memmem(content_type,
                    payload_lengths[0] - (content_type - payload),
                    (unsigned char *) "Content-Type", strlen("Content-Type"));
                second_content_type[0] = '\0';
                request_str = (char *) payload;
            }
            // parse request_str
            boundary_start = strstr(request_str, "Content-Type: multipart/form-data; boundary=");
            boundary_start += strlen("Content-Type: multipart/form-data; boundary=");
            boundary_end = strstr(boundary_start, "\n");
            boundary_length = boundary_end - boundary_start;
            boundary = malloc(boundary_length + 3);
            if (boundary == NULL) {
                fprintf(stderr, "malloc: %s\n", strerror(errno));
                goto cleanup;
            }
            strcpy(boundary, "--");
            strncpy(boundary + 2, boundary_start, boundary_length);
            username = strstr(request_str, "Content-Disposition: form-data; name=\"username\"");
            username += strlen("Content-Disposition: form-data; name=\"username\"");
            username_end = strstr(username, boundary);
            username_length = username_end - username;
            username_copy = malloc(username_length);
            if (username_copy == NULL) {
                fprintf(stderr, "malloc: %s\n", strerror(errno));
                goto cleanup;
            }
            strncpy(username_copy, username, username_length);
            password = strstr(request_str, "Content-Disposition: form-data; name=\"password\"");
            password += strlen("Content-Disposition: form-data; name=\"password\"");
            password_end = strstr(password, boundary);
            password_length = password_end - password;
            password_copy = malloc(password_length);
            if (password_copy == NULL) {
                fprintf(stderr, "malloc: %s\n", strerror(errno));
                goto cleanup;
            }
            strncpy(password_copy, password, password_length);
            username_stripped = calloc(username_length, sizeof(char));
            if (username_stripped == NULL) {
                fprintf(stderr, "calloc: %s\n", strerror(errno));
                goto cleanup;
            }
            stripped_i = 0;
            for (i = 0; i < username_length; i++) {
                if (!isspace(username_copy[i])) {
                    username_stripped[stripped_i] = username_copy[i];
                    ++stripped_i;
                }
            }
            password_stripped = calloc(password_length, sizeof(char));
            if (password_stripped == NULL) {
                fprintf(stderr, "calloc: %s\n", strerror(errno));
                goto cleanup;
            }
            stripped_i = 0;
            for (i = 0; i < password_length; i++) {
                if (!isspace(password_copy[i])) {
                    password_stripped[stripped_i] = password_copy[i];
                    ++stripped_i;
                }
            }
            printf("username = %s\n", username_stripped);
            printf("password = %s\n", password_stripped);
        } else {
            curr = strtok(decoded_payload, "\n");
            while (curr != NULL) {
                body = curr;
                curr = strtok(NULL, "\n");
            }
            username = body + strlen("username=");
            password = strstr(body, "&password=");
            username_length = password - username;
            username[username_length] = '\0';
            password += strlen("&password=");
            printf("username = %s\n", username);
            printf("password = %s\n", password);
            printf("\n--------------------------------------------------\n\n");

            dumper = pcap_dump_open(handle, "data.pcap");
            if (dumper == NULL) {
                fprintf(stderr, "pcap_dump_open: %s\n", errbuf);
                goto cleanup;
            }
            pcap_dump((u_char *) dumper, stored_packet_header, stored_packet);
            pcap_dump_close(dumper);
            reader = pcap_open_offline("data.pcap", errbuf);
            if (reader == NULL) {
                fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
                goto cleanup;
            }
            status = pcap_next_ex(reader, &header, &packet_0);
            if (status == PCAP_ERROR_BREAK) {
                fprintf(stderr, "pcap_next_ex: no more packets to read\n");
                goto cleanup;
            } else if (status == PCAP_ERROR) {
                fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(reader));
                goto cleanup;
            }
            if (link_layer_header_type == DLT_NULL) {
                size_ethernet = sizeof(struct sniff_loopback_bsd);
            } else { // link_layer_header_type == DLT_EN10MB
                size_ethernet = sizeof(struct sniff_ethernet);
            }
            ip = (struct sniff_ip*)(packet_0 + size_ethernet);
            size_ip = IP_HL(ip) * 4;
            tcp = (struct sniff_tcp*)(packet_0 + size_ethernet + size_ip);
            size_tcp = TH_OFF(tcp) * 4;
            payload_0 = (char *)(packet_0 + size_ethernet + size_ip + size_tcp);
            printf("%s\n", payload_0);
        }
    } else {
        for (index = 0; index < payload_lengths[0]; index++) {
            printf("%02x", payloads[0][index]);
        }
        printf("\n");
    }
    error = 0;

cleanup:
    free(password_stripped);
    free(username_stripped);
    free(password_copy);
    free(username_copy);
    free(boundary);
    free(request_str_copy);
    if (reader != NULL) {
        pcap_close(reader);
    }
    if (compiled) {
        pcap_freecode(&fp);
    }
    if (handle != NULL) {
        pcap_close(handle);
    }
    free(stored_packet);
    free(stored_packet_header);
    free(decoded_payload);
    free(payload_lengths);
    for (index = 0; index < payloads_count; index++) {
        free(payloads[index]);
    }
    free(payloads);
    free(loopback_iface);
    if (error) {
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    char *var = getenv("FILE_UPLOAD");
    if (var != NULL && strcmp(var, "1") == 0) {
        file_upload = 1;
    } else {
        file_upload = 0;
    }

    if (argc == 2 && strstr(argv[1], "encrypt") != NULL) {
        encrypted = 1;
    } else {
        encrypted = 0;
    }
    sniff_packets();

    return 0;
}
