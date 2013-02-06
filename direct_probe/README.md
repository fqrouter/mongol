#direct probe

Direct probe use raw socket to send manually created IP packet. It can give us better performance, as
for TCP there is no need to wait for three way handshaking to complete to send following offending payload.
Also, by creating and sending the IP packet directly, it shows the condition to trigger GFW reaction more clearly.