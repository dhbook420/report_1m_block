
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include "ip.h"
#include <fcntl.h>
#include "structure.h"
#include <string>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <set>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* returns packet id */
using namespace std;

void usage() {
    printf("syntax : sudo 1m-block <site list file>\n");
    printf("sample : sudo 1m-block top-1m.txt\n");
}

set<string> hosts;

static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint32_t id = print_pkt(nfa);

    unsigned char *pkt;
	int ret = nfq_get_payload(nfa, &pkt);
    if (ret >= 0) {
		printf("\nreceived %d bytes\n", ret);
		//dump(pkt, ret);
	}

    IpHdr *ip = (IpHdr *)pkt;
    tcpHdr *tcp = (tcpHdr *)(pkt + sizeof(IpHdr));
    unsigned char *http = (unsigned char *)(pkt + sizeof(IpHdr) + tcp->th_off * 4);
    int http_len = ret - (ip->ip_hl * 4) - (tcp->th_off * 4);

    if ((ret <= 0) || (ip->protocol != IpHdr::TCP) || (http_len <= 0))
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    char *host_field = strstr((char*)http, "\r\nHost: ");
    if (host_field)
      {
    	const clock_t begin = clock();
      	host_field += strlen("\r\nHost: ");
        char *end = strchr(host_field, '\r');

        int len;
        if (end) {
            len = end - host_field;
        } else {
            len = strlen(host_field);
        }
		string key(host_field, len);

        if (hosts.count(key))
          {
          	const clock_t end_time = clock();
            const clock_t diff = end_time - begin;
            cout << "Blocked : " << key.c_str() << '\n' << "time diff (sec): " << float(diff) / CLOCKS_PER_SEC << '\n';
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
          }
    	const clock_t end_time = clock();
    	const clock_t diff = end_time - begin;
    	cout << "Not blocked | time diff : " << diff << '\n';
      }
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}



int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;

	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

    if (argc != 2)
    {
      usage();
      return 0;
    }

    const clock_t begin = clock();
    string site_file = argv[1];


	ifstream ifd(site_file.c_str());
    if (!ifd.is_open())
    {
		cerr << "Can't open site file " << site_file << '\n';
        return 1;
    }
	string line;
    while (std::getline(ifd, line))
    {
      	if(!line.empty() && line[0] != '\r')
        {
	    	line.pop_back();
        }
        auto pos = line.find(',');
        line = line.substr(pos + 1);
        hosts.insert(line);
    }

    ifd.close();
	/*
    for (auto it = hosts.begin(); it != hosts.end(); advance(it, 1000))
    {
    	cout << *it << (*it).size() <<'\n';
    }
    */

    const clock_t end = clock();
    const clock_t diff = end - begin;

    char cmd[128];
    sprintf(cmd, "top -b -n 1 -p %d | tail -n +8 | awk '{print $6}'", getpid()); //명령어 작성

	FILE* pipe = popen(cmd, "r");
	if (!pipe) {
		perror("popen");
		return -1;
	}

	char memsize[64];
	if (fgets(memsize, 64, pipe) == nullptr) {
		pclose(pipe);
		std::cerr << "memory read failed\n";
		return -1;
	}
	pclose(pipe);

	cout << "time diff (sec) : " << float(diff) / CLOCKS_PER_SEC << '\n' << "memory usage : " << memsize << '\n';

    return 0;
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}



	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("\n\npkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
