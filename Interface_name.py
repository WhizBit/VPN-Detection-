import psutil

net_if_stats = psutil.net_if_stats()
net_if_addrs = psutil.net_if_addrs()

connected_interfaces = []

for interface, stats in net_if_stats.items():
    if stats.isup:  # Interface is up
        connected_interfaces.append(interface)

print("Connected Network Interfaces:")
print(connected_interfaces[0])
