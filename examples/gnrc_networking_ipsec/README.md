## gnrc_networking_ipsec example

In this example we get the minimal ESP implementation in RIOT OS working to test it against itself and other implementations of ESP.

This example is based on the gnrc_networking udp example, so all networking explanations hold true in this example. Additionally you can use dbfrm cmdline tool to add spd rules and sa entries and thus communicate over encrypted ESP.

# Setup

For now the SPD rules are hardcoded inline at the top of gnrc_ipv6_keyengine.c. Leave out your PROTECTED Traffic Selectors from the SPD since manual SPD Cache entries and their SAs should be entered using the commandline helper dbfrm to simulate dynamic key handling.

# dbfrm --help

{} fields can be NULL'ed when no SA is needed
Input string: action {id}  {spi}  dst  src  proto  port_dst port_src {mode}
	{c_mode} {auth} {hash_key} {enc} {enc_key} {iv} {t_src} {t_dst}

action:		protect, bypass, discard
id:		unique sa id (uint16)
spi:		uint32
dst:		ipv6 address
src:		ipv6 address
proto:		IP protnum or 'any'
port_dst:	port/socket (uint16) or NULL
port_src:	port/socket (uint16) or NULL
mode:		'transport', 'tunnel'
c_mode:		'auth', 'authenc', 'comb'
auth:		'none', 'sha'
hash_key:	Key in lower case hex or '0'
enc:		'none', 'aes', 'chacha', 'mockup'
enc_key:	Key in lower case hex or '0'
iv:	IV in lower case hex or '0'
t_src:		ipv6 address or NULL
t_dst:		ipv6 address or NULL

## Sample setup


Sends and PROTECTs UDP traffic between two instances


#RCV Client:
ifconfig 8 add 2000::2/64

udp server start 666

dbfrm protect '42' '13371337' '2000::2' '2000::1' 17  NULL NULL transport comb none '0' mockup 'b7396d693045f060' '4242424242' NULL NULL


#SND Client:
ifconfig 8 add 2000::1/64

dbfrm protect '42' '13371337' '2000::2' '2000::1' 17  NULL NULL transport comb none '0' mockup 'b7396d693045f060' '4242424242' NULL NULL

udp send 2000::2 666 "In Search of Payload"

