#pragma once

struct sk_buff* bcmon_decode_skb(struct sk_buff* skb);
void pcap_dump(uchar *buf, uint nbytes);
