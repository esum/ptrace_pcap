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
#include <random>
#include <time.h>
#include <unistd.h>

#include <unordered_map>
#include <vector>

constexpr unsigned short default_dst_port = 2321;
constexpr unsigned short default_src_port = 50000;


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

inline void write_ip4_header(int fd, struct in_addr *src_addr, struct in_addr *dst_addr, unsigned short total_length)
{
	unsigned short len = htons(total_length);
	unsigned int src = htonl(src_addr->s_addr);
	unsigned int dst = htonl(dst_addr->s_addr);
	write(fd, "\x45\x00", 2);
	write(fd, &len, 2);
	write(fd, "\x00\x00" "\x00\x00" "\x00" "\x06" "\x00\x00", 8);
	write(fd, &src, 4);
	write(fd, &dst, 4);
}

inline void write_ip6_header(int fd, struct in6_addr *src_addr, struct in6_addr *dst_addr, unsigned short payload_length)
{
	unsigned short len = htons(payload_length);
	write(fd, "\x60\x00\x00\x00", 4);
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
		int dump = open(argv[1], O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
		if (dump == -1) {
			return 1;
		}
		std::random_device rd;
		std::mt19937 mt(rd());
		std::unordered_map<int, unsigned int> seq_in;
		std::unordered_map<int, unsigned int> seq_out;
		std::unordered_map<int, unsigned long> last_syscall;
		std::unordered_map<int, std::pair<std::vector<unsigned char>, unsigned short>> cur_remote_addr;
		std::unordered_map<int, std::pair<std::vector<unsigned char>, unsigned short>> cur_local_addr;
		std::unordered_map<int, std::pair<std::vector<unsigned char>, unsigned short>> binds;
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
					if (regs.rax > 0x7fffffffffff)
						break;
					char *buffer = new char[regs.rax + sizeof(long)];
					bool ip4 = cur_remote_addr.contains(regs.rdi) && cur_remote_addr[regs.rdi].first.size() == 4 || cur_local_addr.contains(regs.rdi) && cur_local_addr[regs.rdi].first.size() == 4;
					if (!seq_in.contains(regs.rdi))
						seq_in[regs.rdi] = mt();
					if (!seq_out.contains(regs.rdi))
						seq_out[regs.rdi] = mt();
					peek_data(pid, (void*)regs.rsi, buffer, regs.rax);
					write_pcap_packet_header(dump, regs.rax + 14 + (ip4 ? 20 : 40) + 20);
					write_ethernet_header(dump, "\x00\x00\x00\x00\x00\x01", "\x00\x00\x00\x00\x00\x02", ip4 ? 0x0800 : 0x86dd);
					if (ip4) {
						struct in_addr src_addr, dst_addr;
						if (cur_local_addr.contains(regs.rdi))
							dst_addr.s_addr = (cur_local_addr[regs.rdi].first[0] << 24) | (cur_local_addr[regs.rdi].first[1] << 16) | (cur_local_addr[regs.rdi].first[2] << 8) | cur_local_addr[regs.rdi].first[3];
						else
							memset(&dst_addr, 0, sizeof(struct in_addr));
						if (cur_remote_addr.contains(regs.rdi))
							src_addr.s_addr = (cur_remote_addr[regs.rdi].first[0] << 24) | (cur_remote_addr[regs.rdi].first[1] << 16) | (cur_remote_addr[regs.rdi].first[2] << 8) | cur_remote_addr[regs.rdi].first[3];
						else
							memset(&src_addr, 0, sizeof(struct in_addr));
						write_ip4_header(dump, &src_addr, &dst_addr, regs.rax + 20 + 20);
					}
					else {
						struct in6_addr src_addr, dst_addr;
						memset(&dst_addr, 0, sizeof(struct in6_addr));
						if (cur_remote_addr.contains(regs.rdi) && cur_remote_addr[regs.rdi].first.size() == 16) {
							for (int i = 0; i < 16; i++)
								src_addr.s6_addr[i] = cur_remote_addr[regs.rdi].first[i];
						}
						else {
							memset(&src_addr, 0, sizeof(struct in6_addr));
							src_addr.s6_addr[0] = 1;
							src_addr.s6_addr[15] = regs.rdi;
						}
						write_ip6_header(dump, &src_addr, &dst_addr, regs.rax + 20);
					}
					if (last_syscall.contains(regs.rdi) && last_syscall[regs.rdi] != regs.orig_rax)
						write_tcp_header(dump, cur_remote_addr.contains(regs.rdi) ? cur_remote_addr[regs.rdi].second : default_dst_port, cur_local_addr.contains(regs.rdi) ? cur_local_addr[regs.rdi].second : default_src_port, seq_in[regs.rdi], seq_out[regs.rdi], 16);
					else
						write_tcp_header(dump, cur_remote_addr.contains(regs.rdi) ? cur_remote_addr[regs.rdi].second : default_dst_port, cur_local_addr.contains(regs.rdi) ? cur_local_addr[regs.rdi].second : default_src_port, seq_in[regs.rdi], 0, 0);
					write(dump, buffer, regs.rax);
					seq_in[regs.rdi] += regs.rax;
					last_syscall[regs.rdi] = regs.orig_rax;
					delete[] buffer;
					}
					break;
				case __NR_write: {
					if (regs.rax > 0x7fffffffffff)
						break;
					char *buffer = new char[regs.rax + sizeof(long)];
					bool ip4 = cur_remote_addr.contains(regs.rdi) && cur_remote_addr[regs.rdi].first.size() == 4;
					if (!seq_in.contains(regs.rdi))
						seq_in[regs.rdi] = mt();
					if (!seq_out.contains(regs.rdi))
						seq_out[regs.rdi] = mt();
					peek_data(pid, (void*)regs.rsi, buffer, regs.rax);
					write_pcap_packet_header(dump, regs.rax + 14 + (ip4 ? 20 : 40) + 20);
					write_ethernet_header(dump, "\x00\x00\x00\x00\x00\x02", "\x00\x00\x00\x00\x00\x01", ip4 ? 0x0800 : 0x86dd);
					if (ip4) {
						struct in_addr src_addr, dst_addr;
						memset(&src_addr, 0, sizeof(struct in_addr));
						dst_addr.s_addr = (cur_remote_addr[regs.rdi].first[0] << 24) | (cur_remote_addr[regs.rdi].first[1] << 16) | (cur_remote_addr[regs.rdi].first[2] << 8) | cur_remote_addr[regs.rdi].first[3];
						write_ip4_header(dump, &src_addr, &dst_addr, regs.rax + 20 + 20);
					}
					else {
						struct in6_addr src_addr, dst_addr;
						memset(&src_addr, 0, sizeof(struct in6_addr));
						if (cur_remote_addr.contains(regs.rdi) && cur_remote_addr[regs.rdi].first.size() == 16) {
							for (int i = 0; i < 16; i++)
								dst_addr.s6_addr[i] = cur_remote_addr[regs.rdi].first[i];
						}
						else {
							memset(&dst_addr, 0, sizeof(struct in6_addr));
							dst_addr.s6_addr[0] = 1;
							dst_addr.s6_addr[15] = regs.rdi;
						}
						write_ip6_header(dump, &src_addr, &dst_addr, regs.rax + 20);
					}
					if (last_syscall.contains(regs.rdi) && last_syscall[regs.rdi] != regs.orig_rax)
						write_tcp_header(dump, default_src_port, cur_remote_addr.contains(regs.rdi) ? cur_remote_addr[regs.rdi].second : default_dst_port, seq_out[regs.rdi], seq_in[regs.rdi], 16);
					else
						write_tcp_header(dump, default_src_port, cur_remote_addr.contains(regs.rdi) ? cur_remote_addr[regs.rdi].second : default_dst_port, seq_out[regs.rdi], 0, 0);
					write(dump, buffer, regs.rax);
					seq_out[regs.rdi] += regs.rax;
					last_syscall[regs.rdi] = regs.orig_rax;
					delete[] buffer;
					}
					break;
				case __NR_close: {
					if (regs.rax > 0x7fffffffffff)
						break;
					bool ip4 = cur_remote_addr.contains(regs.rdi) && cur_remote_addr[regs.rdi].first.size() == 4 || cur_local_addr.contains(regs.rdi) && cur_local_addr[regs.rdi].first.size() == 4;
					write_pcap_packet_header(dump, 14 + (ip4 ? 20 : 40) + 20);
					write_ethernet_header(dump, "\x00\x00\x00\x00\x00\x02", "\x00\x00\x00\x00\x00\x01", ip4 ? 0x0800 : 0x86dd);
					if (ip4) {
						struct in_addr src_addr, dst_addr;
						if (cur_local_addr.contains(regs.rdi))
							src_addr.s_addr = (cur_local_addr[regs.rdi].first[0] << 24) | (cur_local_addr[regs.rdi].first[1] << 16) | (cur_local_addr[regs.rdi].first[2] << 8) | cur_local_addr[regs.rdi].first[3];
						else
							memset(&src_addr, 0, sizeof(struct in_addr));
						if (cur_remote_addr.contains(regs.rdi))
							dst_addr.s_addr = (cur_remote_addr[regs.rdi].first[0] << 24) | (cur_remote_addr[regs.rdi].first[1] << 16) | (cur_remote_addr[regs.rdi].first[2] << 8) | cur_remote_addr[regs.rdi].first[3];
						else
							memset(&dst_addr, 0, sizeof(struct in_addr));
						write_ip4_header(dump, &src_addr, &dst_addr, regs.rax + 20 + 20);
					}
					else {
						struct in6_addr src_addr, dst_addr;
						memset(&src_addr, 0, sizeof(struct in6_addr));
						if (cur_remote_addr.contains(regs.rdi) && cur_remote_addr[regs.rdi].first.size() == 16) {
							for (int i = 0; i < 16; i++)
								dst_addr.s6_addr[i] = cur_remote_addr[regs.rdi].first[i];
						}
						else {
							memset(&dst_addr, 0, sizeof(struct in6_addr));
							dst_addr.s6_addr[0] = 1;
							dst_addr.s6_addr[15] = regs.rdi;
						}
						write_ip6_header(dump, &src_addr, &dst_addr, 20);
					}
					write_tcp_header(dump, cur_local_addr.contains(regs.rdi) ? cur_local_addr[regs.rdi].second : default_src_port, cur_remote_addr.contains(regs.rdi) ? cur_remote_addr[regs.rdi].second : default_dst_port, seq_out[regs.rdi], seq_in[regs.rdi], 4);
					if (seq_in.contains(regs.rdi))
						seq_in.erase(regs.rdi);
					if (seq_out.contains(regs.rdi))
						seq_out.erase(regs.rdi);
					seq_out[regs.rdi] = mt();
					last_syscall[regs.rdi] = regs.orig_rax;
					if (cur_remote_addr.contains(regs.rdi))
						cur_remote_addr.erase(regs.rdi);
					if (cur_local_addr.contains(regs.rdi))
						cur_local_addr.erase(regs.rdi);
					if (binds.contains(regs.rdi))
						binds.erase(regs.rdi);
					}
					break;
				case __NR_connect: {
					if (regs.rax > 0x7fffffffffff)
						break;
					char *buffer = new char[regs.rdx + sizeof(long)];
					peek_data(pid, (void*)regs.rsi, buffer, regs.rdx);
					switch (((struct sockaddr*)buffer)->sa_family) {
						case AF_INET: {
							struct sockaddr_in *addr = (struct sockaddr_in*)buffer;
							cur_remote_addr[regs.rdi] = { {}, ntohs(addr->sin_port) };
							cur_remote_addr[regs.rdi].first.push_back((ntohl(addr->sin_addr.s_addr) & 0xff000000) >> 24);
							cur_remote_addr[regs.rdi].first.push_back((ntohl(addr->sin_addr.s_addr) & 0x00ff0000) >> 16);
							cur_remote_addr[regs.rdi].first.push_back((ntohl(addr->sin_addr.s_addr) & 0x0000ff00) >> 8);
							cur_remote_addr[regs.rdi].first.push_back(ntohl(addr->sin_addr.s_addr) & 0x000000ff);
							}
							break;
						case AF_INET6: {
							struct sockaddr_in6 *addr = (struct sockaddr_in6*)buffer;
							cur_remote_addr[regs.rdi] = { {}, ntohs(addr->sin6_port) };
							for (int i = 0; i < 16; i++)
								cur_remote_addr[regs.rdi].first.push_back(addr->sin6_addr.s6_addr[i]);
							}
							break;
						default:
							break;
					}
					delete[] buffer;
					}
					break;
				case __NR_accept:
				case __NR_accept4: {
					if (regs.rax > 0x7fffffffffff)
						break;
					socklen_t *socklen = new socklen_t;
					peek_data(pid, (void*)regs.rdx, (char*)socklen, sizeof(socklen_t));
					char *buffer = new char[*socklen + sizeof(long)];
					peek_data(pid, (void*)regs.rsi, buffer, *socklen);
					switch (((struct sockaddr*)buffer)->sa_family) {
						case AF_INET: {
							struct sockaddr_in *addr = (struct sockaddr_in*)buffer;
							cur_remote_addr[regs.rax] = { {}, ntohs(addr->sin_port) };
							cur_remote_addr[regs.rax].first.push_back((ntohl(addr->sin_addr.s_addr) & 0xff000000) >> 24);
							cur_remote_addr[regs.rax].first.push_back((ntohl(addr->sin_addr.s_addr) & 0x00ff0000) >> 16);
							cur_remote_addr[regs.rax].first.push_back((ntohl(addr->sin_addr.s_addr) & 0x0000ff00) >> 8);
							cur_remote_addr[regs.rax].first.push_back(ntohl(addr->sin_addr.s_addr) & 0x000000ff);
							}
							break;
						case AF_INET6: {
							struct sockaddr_in6 *addr = (struct sockaddr_in6*)buffer;
							cur_remote_addr[regs.rax] = { {}, ntohs(addr->sin6_port) };
							for (int i = 0; i < 16; i++)
								cur_remote_addr[regs.rax].first.push_back(addr->sin6_addr.s6_addr[i]);
							}
							break;
						default:
							break;
					}
					delete[] buffer;
					if (binds.contains(regs.rdi))
						cur_local_addr[regs.rax] = binds[regs.rdi];
					}
					break;
				case __NR_bind: {
					if (regs.rax > 0x7fffffffffff)
						break;
					char *buffer = new char[regs.rdx + sizeof(long)];
					peek_data(pid, (void*)regs.rsi, buffer, regs.rdx);
					switch (((struct sockaddr*)buffer)->sa_family) {
						case AF_INET: {
							struct sockaddr_in *addr = (struct sockaddr_in*)buffer;
							binds[regs.rdi] = { {}, ntohs(addr->sin_port) };
							binds[regs.rdi].first.push_back((ntohl(addr->sin_addr.s_addr) & 0xff000000) >> 24);
							binds[regs.rdi].first.push_back((ntohl(addr->sin_addr.s_addr) & 0x00ff0000) >> 16);
							binds[regs.rdi].first.push_back((ntohl(addr->sin_addr.s_addr) & 0x0000ff00) >> 8);
							binds[regs.rdi].first.push_back(ntohl(addr->sin_addr.s_addr) & 0x000000ff);
							}
							break;
						case AF_INET6: {
							struct sockaddr_in6 *addr = (struct sockaddr_in6*)buffer;
							binds[regs.rdi] = { {}, ntohs(addr->sin6_port) };
							for (int i = 0; i < 16; i++)
								binds[regs.rdi].first.push_back(addr->sin6_addr.s6_addr[i]);
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
