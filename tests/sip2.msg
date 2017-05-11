INFO sip:+18553623164@10.24.20.47:5070;transport=udp SIP/2.0
Via: SIP/2.0/UDP 192.209.28.49;rport;branch=z9hG4bKHvDg1yStyZ7SK
Max-Forwards: 70
From: "msml" <sip:msml@192.209.28.49>;tag=Fr7DDrH0SUS7B
To: "+18553623164" <sip:+18553623164@10.24.21.90>;tag=10.24.20.47-5070-d4883670d51447c
Call-ID: ac27de05bfe44fa0983014d20da45906
CSeq: 83253780 INFO
User-Agent: HMP-1.2.3-
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, INFO
Supported: timer
Content-Type: application/msml+xml
Content-Length: 198

<?xml version="1.0" encoding="US-ASCII"?>
<msml version="1.1">
	<event name="app.dtmfcompleted" id="conn:Fr7DDrH0SUS7B/dialog:detectdigits">
		<name>dtmf.digits</name>
		<value/>
	</event>
</msml>

