# gnrc_networking_ipsec example

In this example we get the minimal ESP implementation in RIOT OS working to test it against itself and other implementations of ESP.

This example is based on the gnrc_networking udp example, so all networking explanations hold true in this example. Additionally you can use dbfrm cmdline tool to add spd rules and sa entries and thus communicate over encrypted ESP.

# Setup

For now the SPD rules are hardcoded inline at the top of gnrc_ipv6_keyengine.c. Leave out your PROTECTED Traffic Selectors from the SPD since manual SPD Cache entries and their SAs should be entered using the commandline helper dbfrm to simulate dynamic key handling.

# dbfrm --help

Unused optional fields must be NULL'ed
{} fields can be NULL'ed when no SA is needed
Input string: action {id} {spi} dst src proto [port_dst] [port_src] {mode} {auth} {auth_key} {enc} {enc_key} [t_src] [t_dst]

action:		protect, bypass, discard
id:		unique sa id (uint16)
spi:		uint32
dst:		ipv6 address
src:		ipv6 address
proto:		IP protnum or 'any'
port_dst:	port/socket (uint16) or NULL
port_src:	port/socket (uint16) or NULL
mode:		'transport', 'tunnel'
auth:		'none', 'mock'
auth_key:	512bit key in lower case hex
enc:		'none', 'sha', 'chacha', 'mock'
enc_key:	512bit key in lower case hex
t_src:		ipv6 address or NULL
t_dst:		ipv6 address or NULL

# Sample setup

PROTECTS and encrypts UDP traffic from Client#1 to Client#2

#!#! WIP !#!#

Client #1:
ifconfig 8 set addr_long *****

dbfrm protect '123' '571' 'fe80::5c64:73ff:fef9:7c3' 'fe80::c8ff:e6ff:feed:7e8c' 17  NULL NULL transport mock 'bd9a51e0f1e4c30669acf99c052bced782a8d455e89e66da755668e91fac9a378b23ca9c6a34015b3fac37d000faf888ad1b730c1d8e7f2000064fe0ec2f5c96' mock 'b7396d693045f060633ac1653443e2493d26062fca90ce6fa858b8c212925f1cd20da5abd6d76e09b2b10bbc236161214a6e60da55c394183ba39758f192249c' NULL NULL

Test for shorter keys: dbfrm protect '123' '571' 'fe80::5c64:73ff:fef9:7c3' 'fe80::c8ff:e6ff:feed:7e8c' 17  NULL NULL transport mock 'beef' mock 'calf' NULL NULL

Client #2:
ifconfig 8 set addr_long *****

dbfrm protect '123' '571' 'fe80::c8ff:e6ff:feed:7e8c' 'fe80::5c64:73ff:fef9:7c3' 17  NULL NULL transport mock  'bd9a51e0f1e4c30669acf99c052bced782a8d455e89e66da755668e91fac9a378b23ca9c6a34015b3fac37d000faf888ad1b730c1d8e7f2000064fe0ec2f5c96' mock 'b7396d693045f060633ac1653443e2493d26062fca90ce6fa858b8c212925f1cd20da5abd6d76e09b2b10bbc236161214a6e60da55c394183ba39758f192249c' NULL NULL