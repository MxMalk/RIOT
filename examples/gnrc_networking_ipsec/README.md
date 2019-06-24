# gnrc_networking_ipsec example

In this example we get the minimal ESP implementation in RIOT OS working to test it against itself and other implementations of ESP.

This example is based on the gnrc_networking udp example, so all networking explanations hold true in this example. Additionally you can use dbfrm cmdline tool to add spd rules and sa entries and thus communicate over encrypted ESP.

# Setup

For now the SPD rules are hardcoded inline at the top of gnrc_ipv6_keyengine.c. Leave out your PROTECTED Traffic Selectors from the SPD since manual SPD Cache entries and their SAs should be entered using the commandline helper dbfrm to simulate dynamic key handling.

# dbfrm --help

Unused optional fields must be NULL'ed
{} fields can be NULL'ed when no SA is needed
Input string: action  {id}  {spi}  dst  src  proto  [port_dst] [port_src] {mode}
	{auth} {auth_key} {enc} {enc_key} [t_src] [t_dst]

action:		protect, bypass, discard
id:		unique sa id (uint16)
spi:		uint32
dst:		ipv6 address
src:		ipv6 address
proto:		IP protnum or 'any'
port_dst:	port/socket (uint16) or NULL
port_src:	port/socket (uint16) or NULL
mode:		'transport', 'tunnel'
auth:		'none', 'sha'
auth_key:	512bit key in lower case hex
enc:		'none', 'sha', 'chacha'
enc_key:	512bit key in lower case hex
t_src:		ipv6 address or NULL
t_dst:		ipv6 address or NULL