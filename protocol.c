#include "protocol.h"

void decode_header(struct Header *header) {
    header->id = ntohs(header->id);
    header->qdcount = ntohs(header->qdcount);
    header->ancount = ntohs(header->ancount);
    header->nscount = ntohs(header->nscount);
    header->arcount = ntohs(header->arcount);
}

void encode_header(struct Header *header) {
    header->id = htons(header->id);
    header->qdcount = htons(header->qdcount);
    header->ancount = htons(header->ancount);
    header->nscount = htons(header->nscount);
    header->arcount = htons(header->arcount);
}

unsigned int form_standard_response(unsigned char *buffer, char *domain_name, unsigned int ip, unsigned int *question_size) {
    // Header
    Header *header = (Header *)buffer;
    header->id = 0;
    header->qr = 1;
    header->opcode = header->aa = header->tc = 0;
    header->rd = header->ra = 1;
    header->z = header->ad = header->cd = 0;
    if (ip) {
        header->rcode = 0;
        header->ancount = 1;
    }
    else {
        header->rcode = 3;
        header->ancount = 0;
    }
    header->qdcount = 1;
    header->nscount = header->arcount = 0;
    encode_header(header);

    // Question
    unsigned int domain_name_size = strlen(domain_name);
    unsigned char *qname = (unsigned char *)(buffer + 12);
    *qname = 0;
    for (int k = 0, l = 1; k <= domain_name_size; ++k, ++l) {
        if (domain_name[k] != '.' && domain_name[k]) {
            *(qname + l) = domain_name[k];
            ++(*qname);
        }
        else {
            qname += (*qname) + 1;
            *qname = l = 0;
        }
    }
    unsigned short *qtype = (unsigned short *)(qname + 1);
    *qtype = htons(1);
    unsigned short *qclass = qtype + 1;
    *qclass = htons(1);
    *question_size = (unsigned char *)(qclass + 1) - buffer;
    if (!ip) {
        return *question_size;
    }

    // Answer
    unsigned short *name = qclass + 1;
    *name = htons(0xc00c);
    unsigned short *type = name + 1;
    *type = htons(1);
    unsigned short *class = type + 1;
    *class = htons(1);
    unsigned long *ttl = (unsigned long *)(class + 1);
    *ttl = htonl(DEFAULT_TTL);
    unsigned short *rdlength = (unsigned short *)(ttl + 1);
    *rdlength = htons(4);
    unsigned int *rdata = (unsigned int *)(rdlength + 1);
    *rdata = htonl(ip);

    return (unsigned char *)(rdata + 1) - buffer;
}