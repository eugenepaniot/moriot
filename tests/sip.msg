INVITE sip:msml@192.209.28.48 SIP/2.0
Via: SIP/2.0/UDP 10.24.20.103:5070;rport;branch=z9hG4bKPj132a670d-137d-4072-b141-626171f6f505
Max-Forwards: 70
User-Agent: RC_SIPWRP_20.103
From: "9990056552532533" <sip:9990056552532533@192.209.28.16>;tag=10.24.20.103-5070-234152a5-43be-4a8c
To: "msml" <sip:msml@192.209.28.48>
Contact: <sip:9990056552532533@10.24.20.103:5070;transport=udp>
Call-ID: b0e0f39b-dadf-4c65-8170-b51e7ab9cb8d
CSeq: 1581 INVITE
p-rc-session-id: 99900x5DYRcj3ElDk9evioTr7VRIgCu6
Call-Info: <99900x5DYRcj3ElDk9evioTr7VRIgCu6>;purpose=info
Allow: SUBSCRIBE, NOTIFY, REFER, INVITE, ACK, BYE, CANCEL, UPDATE, INFO
Supported: replaces, timer, diversion
Session-Expires: 3600
Min-SE: 90
Content-Type: application/sdp
Content-Length:   316

v=0
o=- 3447 2987 IN IP4 172.16.13.87
s=SmcSip
c=IN IP4 172.16.13.87
t=0 0
m=audio 13276 RTP/AVP 0 3 8 4 18 19 101
a=rtpmap:0 pcma/8000
a=rtpmap:3 gsm/8000
a=rtpmap:8 pcmu/8000
a=rtpmap:4 g723/8000
a=rtpmap:18 g729/8000
a=rtpmap:19 cn/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
