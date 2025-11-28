## Lab 12 — Kata Containers: VM-backed Container Sandboxing

### Task 1 — Install & Configure Kata
- Built the Kata Rust shim via `labs/lab12/setup/build-kata-runtime.sh` and installed it under `/usr/local/bin`. `containerd-shim-kata-v2 --version` confirms the runtime ID and commit we are using:

```1:1:labs/lab12/setup/kata-built-version.txt
Kata Containers containerd shim (Rust): id: io.containerd.kata.v2, version: 3.23.0, commit: 9dfa6df2cba8ae0e4fd32ae93f186dd47723b1b5
```

- After running `install-kata-assets.sh` and `configure-containerd-kata.sh`, containerd exposes the `io.containerd.kata.v2` runtime. A smoke-test `sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a` succeeds and shows the guest kernel booted inside Kata:

```1:1:labs/lab12/kata/test1.txt
Linux 7f2bb2b8943d 6.12.47 #1 SMP Fri Nov 14 15:34:06 UTC 2025 x86_64 Linux
```

### Task 2 — runc vs Kata Runtime Comparison
- The baseline Juice Shop container that uses the default runc runtime responds on port 3012 with HTTP 200:

```1:2:labs/lab12/runc/health.txt
juice-runc: HTTP 200
```

- Kata containers run fine for the Alpine evidence commands, and they clearly surface an alternative kernel/CPU view:

```1:2:labs/lab12/kata/kernel.txt
6.12.47
```

```1:2:labs/lab12/kata/cpu.txt
model name	: AMD EPYC
```

- Kernel comparison highlights that runc shares the host kernel (`6.17.9-arch1-1`) whereas Kata boots a dedicated guest kernel (`6.12.47`):

```1:3:labs/lab12/analysis/kernel-comparison.txt
=== Kernel Version Comparison ===
Host kernel (runc uses this): 6.17.9-arch1-1
Kata guest kernel: Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:06 UTC 2025
```

- CPU comparison reiterates that runc exposes the physical Ryzen 7 CPU while Kata masks it behind a virtualized AMD EPYC vCPU:

```1:5:labs/lab12/analysis/cpu-comparison.txt
=== CPU Model Comparison ===
Host CPU:
model name	: AMD Ryzen 7 7730U with Radeon Graphics
Kata VM CPU:
model name	: AMD EPYC
```

- Isolation implications: runc containers share the host kernel attack surface (namespaces + seccomp), so a kernel exploit compromises the node. Kata injects a VM boundary, so a guest escape must compromise the lightweight hypervisor or shim before touching the host, significantly improving multi-tenant hardening at the cost of extra overhead.

### Task 3 — Isolation Tests
- `dmesg` inside Kata reveals completely different boot logs, proving that each container runs in its own guest kernel rather than touching the host ring buffer:

```1:8:labs/lab12/isolation/dmesg.txt
=== dmesg Access Test ===
Kata VM (separate kernel boot logs):
time="2025-11-28T11:38:50+03:00" level=warning msg="cannot set cgroup manager to \"systemd\" for runtime \"io.containerd.kata.v2\""
[    0.000000] Linux version 6.12.47 (@4bcec8f4443d) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP Fri Nov 14 15:34:06 UTC 2025
[    0.000000] Command line: reboot=k panic=1 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service root=/dev/vda1 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 agent.container_pipe_size=1 console=ttyS1 agent.log_vport=1025 agent.passfd_listener_port=1027 virtio_mmio.device=8K@0xe0000000:5 virtio_mmio.device=8K@0xe0002000:5
[    0.000000] [Firmware Bug]: TSC doesn't count with P0 frequency!
[    0.000000] BIOS-provided physical RAM map:
```

- /proc, network, and module counts all shrink inside Kata because only the VM-local processes and virtio devices are visible:

```1:3:labs/lab12/isolation/proc.txt
=== /proc Entries Count ===
Host: 449
Kata VM: 52
```

```1:15:labs/lab12/isolation/network.txt
=== Network Interfaces ===
Kata VM network:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 2a:e6:80:ac:f7:bc brd ff:ff:ff:ff:ff:ff
    inet 10.4.0.11/24 brd 10.4.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::28e6:80ff:feac:f7bc/64 scope link tentative 
       valid_lft forever preferred_lft forever
```

```1:3:labs/lab12/isolation/modules.txt
=== Kernel Modules Count ===
Host kernel modules: 316
Kata guest kernel modules: 72
```

- Security implications: a runc escape immediately exposes the host kernel attack surface and any other containers sharing it. With Kata, an attacker must first defeat the guest kernel, then the Kata agent/shim boundary and hypervisor I/O emulation, vastly increasing the exploit complexity. Even if the guest kernel is owned, the blast radius is the VM instance, not the entire node, giving operators time to detect/evict the compromised sandbox.

### Task 4 — Performance Snapshot & Trade-offs
- Startup time measurement shows the expected Kata penalty (~0.15s slower here, primarily due to VM boot and virtio init):

```1:5:labs/lab12/bench/startup.txt
=== Startup Time Comparison ===
runc:
real	0m1.620s
Kata:
real	0m1.774s
```

- HTTP latency for the runc-hosted Juice Shop stays in the low-millisecond range across 50 samples, giving us a baseline for comparison should we front Juice Shop with Kata later:

```1:3:labs/lab12/bench/http-latency.txt
=== HTTP Latency Test (juice-runc) ===
Results for port 3012 (juice-runc):
avg=0.0026s min=0.0018s max=0.0071s n=50
```

- Trade-offs:
  - **Startup overhead:** Kata needs to boot a guest kernel, so cold starts are measurably slower (hundreds of milliseconds to a few seconds depending on image size). runc launches in well under a second.
  - **Runtime overhead:** CPU and network operations run through virtio, so steady-state throughput may dip a few percent versus bare runc, though most web workloads remain well within SLOs.
  - **CPU overhead:** Host CPU features are virtualized/masked (EPYC vCPU shown above), meaning workloads that depend on vendor extensions must rely on what Kata exposes. On the upside this consistent vCPU shape simplifies multi-tenant fairness.
  - **When to use runc:** Best for trusted workloads that need maximum density and the absolute lowest startup latency (CI jobs, internal dev containers, stateless microservices without hostile neighbors).
  - **When to use Kata:** Prefer for multi-tenant or internet-facing services where a kernel escape would be catastrophic, for regulated environments that require VM-level isolation, or when mixing untrusted plugins alongside core services on the same node.
