#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <syscall.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <time.h>
#include <unistd.h>

//#include <queue>
#include <unordered_map>
#include <vector>


typedef union {
	long l;
	char b[sizeof(long)];
} word;

void peek_data(pid_t pid, void *addr, char *buf, size_t len)
{
	word data;
	int i = 0, j = len / sizeof(long);
	while (i < j) {
		data.l = ptrace(PTRACE_PEEKDATA, pid, (char*)addr + i * sizeof(long), NULL);
		memcpy(buf, data.b, sizeof(long));
		buf += sizeof(long);
		i++;
	}
	j = len % sizeof(long);
	if (j) {
		data.l = ptrace(PTRACE_PEEKDATA, pid, (char*)addr + i * sizeof(long), NULL);
		memcpy(buf, data.b, j);
	}
}

inline void write_pcap_header(int fd)
{
	// Use a nanosecond PCAP with ethernet
	write(fd, "\xa1\xb2\x3c\x4d" "\x00\x02" "\x00\x04" "\x00\x00\x00\x00\x00\x00\x00\x00" "\x00\x00\xff\xff", 20);
	write(fd, "\x00\x00\x00\x01", 4);
}

inline void write_pcap_packet_header(int fd, unsigned int data_length)
{
	unsigned int len = htonl(data_length);
	struct timespec tp;
	clock_gettime(CLOCK_REALTIME, &tp);
	unsigned int tv_sec = htonl(tp.tv_sec);
	unsigned int tv_nsec = htonl(tp.tv_nsec);
	write(fd, &tv_sec, 4);
	write(fd, &tv_nsec, 4);
	write(fd, &len, 4);
	write(fd, &len, 4);
}

inline void write_ethernet_header(int fd, char const *dst_mac, char const *src_mac, unsigned short ethertype)
{
	unsigned short type = htons(ethertype);
	write(fd, dst_mac, 6);
	write(fd, src_mac, 6);
	write(fd, &type, 2);
}

inline void write_ip6_header(int fd, struct in6_addr *src_addr, struct in6_addr *dst_addr, unsigned short payload_length)
{
	unsigned short len;
	write(fd, "\x60\x00\x00\x00", 4);
	len = htons(payload_length);
	write(fd, &len, 2);
	write(fd, "\x06\x00", 2);
	write(fd, src_addr->s6_addr, 16);
	write(fd, dst_addr->s6_addr, 16);
}

inline void write_tcp_header(int fd, unsigned short src_port, unsigned short dst_port, unsigned int seq, unsigned int ack, unsigned char flags = 0)
{
	unsigned short source_port = htons(src_port);
	unsigned short destination_port = htons(dst_port);
	unsigned int sequence = htonl(seq);
	unsigned int acknowlegdement = htonl(ack);
	write(fd, &source_port, 2);
	write(fd, &destination_port, 2);
	write(fd, &sequence, 4);
	write(fd, &acknowlegdement, 4);
        write(fd, "\x50", 1);
	write(fd, &flags, 1);
	write(fd, "\xff\xff" "\x00\x00\x00\x00", 6);
}

int main(int argc, char *argv[])
{
	pid_t pid;
	if (argc <= 2)
		return 1;

	if (pid = fork()) {
		if (pid == -1)
			return 1;
		int status;
		bool cont = false;
		//std::unordered_map<int, std::queue<std::tuple<std::optional<struct sockaddr>, bool, char*>>> buffer_data;
		int dump = open(argv[1], O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
		if (dump == -1) {
			return 1;
		}
		std::unordered_map<int, unsigned int> seq_in;
		std::unordered_map<int, unsigned int> seq_out;
		std::unordered_map<int, unsigned long> last_syscall;
		std::unordered_map<int, std::pair<std::vector<unsigned char>, unsigned short>> cur_addr;
		write_pcap_header(dump);
		while (waitpid(pid, &status, 0) && !WIFEXITED(status)) {
			struct user_regs_struct regs;
			if (cont) {
				cont = false;
				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
				continue;
			}
			ptrace(PTRACE_GETREGS, pid, NULL, &regs);
			switch (regs.orig_rax) {
				case __NR_read: {
					char *buffer = new char[regs.rdx + sizeof(long)];
					struct in6_addr src_addr, dst_addr;
					if (!seq_in.contains(regs.rdi))
						seq_in[regs.rdi] = 0;
					if (!seq_out.contains(regs.rdi))
						seq_out[regs.rdi] = 0;
					memset(&dst_addr, 0, sizeof(struct in6_addr));
					if (cur_addr.contains(regs.rdi)) {
						for (int i = 0; i < 16; i++)
							src_addr.s6_addr[i] = cur_addr[regs.rdi].first[i];
					}
					else {
						memset(&src_addr, 0, sizeof(struct in6_addr));
						src_addr.s6_addr[0] = 1;
						src_addr.s6_addr[15] = regs.rdi;
					}
					peek_data(pid, (void*)regs.rsi, buffer, regs.rdx);
					write_pcap_packet_header(dump, regs.rdx + 14 + 40 + 20);
					write_ethernet_header(dump, "\x00\x00\x00\x00\x00\x01", "\x00\x00\x00\x00\x00\x02", 0x86dd);
					write_ip6_header(dump, &src_addr, &dst_addr, regs.rdx + 20);
					if (last_syscall.contains(regs.rdi) && last_syscall[regs.rdi] != regs.orig_rax)
						write_tcp_header(dump, cur_addr.contains(regs.rdi) ? cur_addr[regs.rdi].second : 22, 50000, seq_in[regs.rdi], seq_out[regs.rdi], 16);
					else
						write_tcp_header(dump, cur_addr.contains(regs.rdi) ? cur_addr[regs.rdi].second : 22, 50000, seq_in[regs.rdi], 0, 0);
					write(dump, buffer, regs.rdx);
					seq_in[regs.rdi] += regs.rdx;
					last_syscall[regs.rdi] = regs.orig_rax;
					delete[] buffer;
					}
					break;
				case __NR_write: {
					char *buffer = new char[regs.rdx + sizeof(long)];
					struct in6_addr src_addr, dst_addr;
					if (!seq_in.contains(regs.rdi))
						seq_in[regs.rdi] = 0;
					if (!seq_out.contains(regs.rdi))
						seq_out[regs.rdi] = 0;
					memset(&src_addr, 0, sizeof(struct in6_addr));
					if (cur_addr.contains(regs.rdi)) {
						for (int i = 0; i < 16; i++)
							dst_addr.s6_addr[i] = cur_addr[regs.rdi].first[i];
					}
					else {
						memset(&dst_addr, 0, sizeof(struct in6_addr));
						dst_addr.s6_addr[0] = 1;
						dst_addr.s6_addr[15] = regs.rdi;
					}
					peek_data(pid, (void*)regs.rsi, buffer, regs.rdx);
					write_pcap_packet_header(dump, regs.rdx + 14 + 40 + 20);
					write_ethernet_header(dump, "\x00\x00\x00\x00\x00\x02", "\x00\x00\x00\x00\x00\x01", 0x86dd);
					write_ip6_header(dump, &src_addr, &dst_addr, regs.rdx + 20);
					if (last_syscall.contains(regs.rdi) && last_syscall[regs.rdi] != regs.orig_rax)
						write_tcp_header(dump, 50000, cur_addr.contains(regs.rdi) ? cur_addr[regs.rdi].second : 22, seq_out[regs.rdi], seq_in[regs.rdi], 16);
					else
						write_tcp_header(dump, 50000, cur_addr.contains(regs.rdi) ? cur_addr[regs.rdi].second : 22, seq_out[regs.rdi], 0, 0);
					write(dump, buffer, regs.rdx);
					seq_out[regs.rdi] += regs.rdx;
					last_syscall[regs.rdi] = regs.orig_rax;
					delete[] buffer;
					}
					break;
				case __NR_close: {
					struct in6_addr src_addr, dst_addr;
					memset(&dst_addr, 0, sizeof(struct in6_addr));
					if (cur_addr.contains(regs.rdi)) {
						for (int i = 0; i < 16; i++)
							src_addr.s6_addr[i] = cur_addr[regs.rdi].first[i];
					}
					else {
						memset(&src_addr, 0, sizeof(struct in6_addr));
						src_addr.s6_addr[0] = 1;
						src_addr.s6_addr[15] = regs.rdi;
					}
					write_pcap_packet_header(dump, 14 + 40 + 20);
					write_ethernet_header(dump, "\x00\x00\x00\x00\x00\x02", "\x00\x00\x00\x00\x00\x01", 0x86dd);
					write_ip6_header(dump, &src_addr, &dst_addr, 20);
					write_tcp_header(dump, 50000, 22, seq_out[regs.rdi], seq_in[regs.rdi], 4);
					seq_in[regs.rdi] = 0;
					seq_out[regs.rdi] = 0;
					last_syscall[regs.rdi] = regs.orig_rax;
					if (cur_addr.contains(regs.rdi))
						cur_addr.erase(regs.rdi);
					}
					break;
				case __NR_connect: {
					char *buffer = new char[regs.rdx + sizeof(long)];
					peek_data(pid, (void*)regs.rsi, buffer, regs.rdx);
					switch (((struct sockaddr*)buffer)->sa_family) {
						/* case AF_INET: {
							struct sockaddr_in *addr = (struct sockaddr_in*)buffer;
							cur_addr[regs.rdi] = { {}, addr->sin_port };
							}
							break; */
						case AF_INET6: {
							struct sockaddr_in6 *addr = (struct sockaddr_in6*)buffer;
							cur_addr[regs.rdi] = { {}, ntohs(addr->sin6_port) };
							for (int i = 0; i < 16; i++) {
								cur_addr[regs.rdi].first.push_back(addr->sin6_addr.s6_addr[i]);
							}
							}
							break;
						default:
							break;
					}
					delete[] buffer;
					}
					break;
				default:
					break;
			}
			cont = true;
			ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		}
	}
	else {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execvp(argv[2], &argv[2]);
	}

	return 0;
}
