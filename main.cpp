#include "proto_structures.h"
#include <cstdlib>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <signal.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <map>
#include <vector>
#include <cstdint>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
namespace jw{
	struct tri{
		struct nod{
			std::map<uint64_t,nod*>arr;
		}* root;
		tri(){
			root=new nod;
		}
		void add(std::string x){
			nod* n=root;
			for(int i=0;i<=x.size();i+=8){
				uint64_t y=0;
				if(i+8<x.size())
					memcpy(&y,&x[i],8);
				else
					memcpy(&y,&x[i],x.size()-i);
				auto it=n->arr.find(y);
				if(it==n->arr.end()){
					nod* nxt=new nod;
					n->arr[y]=nxt;
					n=nxt;
				}
				else
					n=it->second;
			}
		}
		void extract(std::vector<uint64_t> &res,nod* n){
			res.push_back(n->arr.size());
			for(auto[i,k]:n->arr)
				res.push_back(i);
			int tmp=res.size();
			for(auto[i,k]:n->arr)
				res.push_back(0);
			for(auto[i,k]:n->arr){
				res[tmp]=res.size()-tmp;
				tmp++;
				extract(res,k);
			}
		}
	};
	
	struct stringmatch:private std::vector<uint64_t>{
		stringmatch(std::string filename){
			int flag=1;
			try{
				flag=std::filesystem::last_write_time(std::filesystem::path(filename))
					>=std::filesystem::last_write_time(std::filesystem::path(filename+".tmp.bin"));
			}
			catch(...){}
			if(flag){
				tri mytri;
				std::ifstream org(filename);
				for(int i=1;;i++){
					int j;char _;std::string s;org>>j>>_>>s;
					if(i!=j)break;
					mytri.add(s);
				}
				mytri.extract(*static_cast<vector<uint64_t>*>(this),mytri.root);
				std::ofstream cache(filename+".tmp.bin",std::ios_base::binary|std::ios_base::out);
				cache.write((char*)&front(),8*size());
			}
			else{
				std::ifstream cache(filename+".tmp.bin",std::ios_base::binary|std::ios_base::in);
				while(!cache.eof()){
					emplace_back();
					cache.read((char*)&back(),8);
				}
			}
		}
		inline bool match(const unsigned char* x,int len){ // <- tcp payload
			const unsigned char* end=x+len;//std::cout<<x<<std::endl;
			if(len<5)return false;
			if(memcmp(x,"GET",3)&&memcmp(x,"POST",4))return false;
			for(;;){
				while(x!=end&&*x++!='\n');
				if(x+6>=end)return false;
				if(*x++=='\r')return false;
				if(*(int*)x++==ntohl('ost:')){ // x->st: *
					auto it=begin();
					for(uint64_t* y=(uint64_t*)(x+4);y+1<(uint64_t*)end;y++){
						uint64_t yy=*y;
						int flag=0;
						for(int i=0;i<64;i+=8){
							flag|=(yy>>i&0xff)=='\r';
							if(flag){
								yy=yy<<64-i>>64-i;
								break;
							}
						}
						int tsiz=*it;
						it=lower_bound(it+1,it+tsiz+1,yy);
						if(*it!=yy)
							return false;
						if(flag){
							std::cout<<"blocked"<<std::endl;
							return true;
						}
						it+=tsiz;
						it+=*it;
					}
					return false;
				}
			}
		}
	};
}
void sigintHandler(int sig)
{
	system("iptables -F");
	exit(0);
}

#define TOKEN_PASTE(x, y) x##y
#define CAT(x,y) TOKEN_PASTE(x,y)
#define ignore_bytes(n) uint8_t CAT(nevermind,__LINE__)[n];

constexpr int is_little_endian(){
	uint16_t x=1;
	return *(uint8_t*)&x;
}

jw::stringmatch forbidden("./top-1m.csv");

struct tcp_port{
	static const int siz=2;
	uint16_t num; // network order
}__attribute__((packed));

struct tcp_header{
	tcp_port src;
	tcp_port dst;
	ignore_bytes(8)
	uint8_t header_size_big : 4;
	uint8_t header_size_little : 4;
	ignore_bytes(7)
	uint32_t upper_layer[1];
	inline bool prn(int len){
		int header_size=is_little_endian()?header_size_little:header_size_big;
		return ntohs(dst.num)==80&&forbidden.match((uint8_t*)(upper_layer+header_size-5),len-header_size*4);
	}
}__attribute__((packed));

struct ipv4_header{
	uint8_t header_size_little : 4;
	uint8_t header_size_big : 4;
	
	ignore_bytes(1)
	uint16_t ip_size;
	ignore_bytes(5)
	uint8_t protocall;
	ignore_bytes(2)
	ipv4_addr src;
	ipv4_addr dst;
	uint32_t upper_layer[1];
	inline bool prn(){
		int header_size=is_little_endian()?header_size_little:header_size_big;
		return protocall==0x06&&((tcp_header*)(upper_layer+header_size-5))->prn(ntohs(ip_size));
	}
}__attribute__((packed));

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *tb, void *ddata)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ",
		//	ntohs(ph->hw_protocol), ph->hook, id);
	}

	ret = nfq_get_payload(tb, &data);
	bool flag=0;
	if (ret >= 0){
		//printf("payload_len=%d\n", ret);
		flag=((ipv4_header*)data)->prn();
	}
	//fputc('\n', stdout);
	//printf("entering callback\n");
	
	return nfq_set_verdict(qh, id, flag?NF_DROP:NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	
	system("iptables -F");
	system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");
	if (signal(SIGINT, sigintHandler) == SIG_ERR){
		printf("signal setting error\n");
		exit(1);
	}
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

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
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
	system("iptables -F");
	exit(0);
}

