# ptrace_pcap

`ptrace_pcap` is a tool that produces a PCAP file by intercepting the `read` and `write` syscalls made by a program.

It tries its best to identify the destination and source IP addresses and ports by intercepting the `accept` and `connect` syscalls.

When no IP address is found for a file descriptor id defaults to IPv6 discard addresses (`100:: + file descriptor number`).

A dummy ethernet layer is also added in the PCAP in order to support both IPv4 and IPv6.


## Compiling

`ptrace_pcap` is written in C++20 it can be compiled with this command:

```bash
g++ -std=C++20 ptrace_pcap.cc -o ptrace_pcap
```


## Running

The first argument is the dump PCAP file and is followed by the command, for instance:

```bash
./ptrace_pcap dump.pcap command [args...]
```

Be careful when sharing PCAP files produced by `ptrace_pcap` as any file read or written by the traced program will be part of the dump (for example SSH keys read when running the SSH client).


## Limitations

Currently the produced PCAP files are readable with tcpdump or wireshark but are not very clean, all `close` syscalls results into `RST` flags being sent in dummy TCP packets.

UDP is not supported.

Packets being reconstructed with `read` and `write` syscalls it is very likely that the dump does not reflect the size of the buffers sent over the connection (for instance when the client reads less than the size of the packet or when the packet is fragmented).

No address is retrieved from the host network configuration. Also the traced program may not be in the same network namespace as the tracer so it is difficult to correctly guess source addresses for clients and destination addresses for servers.
