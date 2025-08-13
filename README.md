# TLS VPN

This is a vpn library based on Transport Layer Security. Encryption and decryption part is
handled by TLS. The developer is supposed to implement SSL socket server and multiple
clients logic management themselves.

This library is supposed to be building block for creating a custom vpn server
solution. It is still in development.

## Creating tun and enabling packet routing

```bash

# Setup tun
sudo ip tuntap add dev tun0 mode tun
sudo ip link set dev tun0 up
sudo ip addr add 10.0.0.1/24 dev tun0

# Setup nat
sudo nft add table ip nat
sudo nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }
sudo nft add rule ip nat postrouting oifname "wlp2s0" masquerade # Replace interfacename wlp2s0 with actual interface.
```
