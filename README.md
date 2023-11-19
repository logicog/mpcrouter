# What's this?
MPCRouter is a web-based administration tool to convert you Mini-/MicroPC
with at least 2 Ethernet ports into a Home-Router. It is installed on top of
any any standard Linux distribution (for Debian 12 packages are supported).
MPCRouter allows you to monitor and administrate the router remotely or
locally through a web-page. It aims to provide the following advantages over
router-specific distribuitons (e.g. OpenWRT):
- Graphical install, no hardware fiddling needed, in case of network
misconfiguration, just use a local console for recovery
- Very high NAT performance (e.g. for Fiber to the Home or GBit routing)
- Standard Linux distribution in combination with moderately powerful router
allows to install other services on the same machine using normal
distribution packages

Tested on:
- MINIX NEO J51-C8 Max (512GB SSD, 8GB RAM, Intel Jasper Lake N5105, Dual
2.GBit Ethernet)
- Zbox CI331 nano (128GBit SSD, 8GBit RAM, Intel Jasper Lake N5100, Dual
1GBit Ethernet)

Note that while it is not difficult to also provide a Wifi Access Point
throught the Wifi 5/6 adapters of these devices, setup will need to be done
manually at this point using hostapd and bridged LAN-side interface.

# Installation
Follow the instruction in INSTALL.

