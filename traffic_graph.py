from collections import deque

tcp_history = deque(maxlen=30)
udp_history = deque(maxlen=30)
icmp_history = deque(maxlen=30)
arp_history = deque(maxlen=30)