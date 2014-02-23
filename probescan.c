/*
 * Copyright (c) 2014 Alexander Schrijver <alex@flupzor.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This program reads an PCAP file and parses the probe frames inside. 
 * 
 * N.B. That I haven't read 802.11 specification very carefully.
 *
 */

#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include <net80211/ieee80211.h>
#include <net80211/ieee80211_radiotap.h>

extern const char *__progname;

void
ps_usage(void)
{
	fprintf(stderr, "usage: %s pcap_dump", __progname);
	exit(EXIT_FAILURE);
}

struct ps_probe_frame {
	struct pcap_pkthdr			*pcap_pkt_hdr;
	const u_char				*pcap_pkt_ptr;

	struct ieee80211_radiotap_header	*radiotap_hdr;

	struct ieee80211_frame			*ieee80211_frame_hdr;

	u_int8_t				*ieee80211_elements;

	u_int8_t				 ieee80211_type;
	u_int8_t				 ieee80211_subtype;
	u_int8_t				 ieee80211_seq;
	u_int8_t				 ieee80211_frag;

	char		 			 ieee80211_nwid[IEEE80211_NWID_LEN + 1];

	int					 invalid_frame;
};

int
ps_parse_nwid_elem(struct ps_probe_frame *probe_frame, const u_char *buf)
{
	const u_char	*nwid_ptr;
	uint8_t		 element_id = 0;
	uint8_t		 nwid_length = 0;
	int		 i;

	element_id = buf[0];
	nwid_length = buf[1];

	if (element_id != IEEE80211_ELEMID_SSID) {
		probe_frame->invalid_frame = 1;
		return 0;
	}

	if (nwid_length > IEEE80211_NWID_LEN || nwid_length == 0) {
		probe_frame->invalid_frame = 1;
		return 0;
	}

	nwid_ptr = buf + 2;

	for (i = 0; i < nwid_length; i++) {
		if (isprint(nwid_ptr[i]))
			probe_frame->ieee80211_nwid[i] = nwid_ptr[i];
		else
			probe_frame->ieee80211_nwid[i] = '?';
	}

	probe_frame->ieee80211_nwid[i] = '\0';

	return 0;
}

int
ps_parse_element_list(struct ps_probe_frame *probe_frame, const u_char *buf, size_t length)
{
	uint8_t		 element_id, element_length;
	int		 i;
	const u_char	*elm_ptr;
	size_t		 data_left = length;

	elm_ptr = buf;

	for (;;) {
		if (data_left < 2)
			return 0;
			
		element_id = elm_ptr[0];
		element_length = elm_ptr[1];

		data_left -= 2;

		if (data_left < element_length)
			return 0;

		data_left -= element_length;

		if (element_id == IEEE80211_ELEMID_SSID)
			ps_parse_nwid_elem(probe_frame, elm_ptr);

		elm_ptr += element_length + 2;
	}

}

int
ps_parse_80211_probe(struct ps_probe_frame *probe_frame, const u_char *buf, size_t length)
{
	struct ieee80211_frame	*frame = (struct ieee80211_frame *)buf;
	uint8_t			 subtype, type;
	const u_char		*elements;
	uint16_t		 seq;

	// Drop incomplete frames.
	if (length < sizeof(struct ieee80211_frame))
		return 0;

	probe_frame->ieee80211_subtype = subtype = frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	probe_frame->ieee80211_type = type = frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK;

	seq =  letoh16(*(u_int16_t *)frame->i_seq);

	probe_frame->ieee80211_seq = seq >> IEEE80211_SEQ_SEQ_SHIFT;
	probe_frame->ieee80211_frag = seq & IEEE80211_SEQ_FRAG_MASK;

	if (type != IEEE80211_FC0_TYPE_MGT &&
	    subtype != IEEE80211_FC0_SUBTYPE_PROBE_REQ)
		return 0;

	elements = buf + sizeof(*frame);

	probe_frame->ieee80211_frame_hdr = frame;
	probe_frame->ieee80211_elements = (u_int8_t *)elements;

	return ps_parse_element_list(probe_frame, elements, length - sizeof(*frame));
}

int
ps_parse_radiotap(struct ps_probe_frame *probe_frame, const u_char *buf, size_t length)
{
	struct ieee80211_radiotap_header *rtap;

	// Drop incomplete packets
	if (length < sizeof(struct ieee80211_radiotap_header))
		return 0;

	rtap = (struct ieee80211_radiotap_header *)buf;

	probe_frame->radiotap_hdr = rtap;

	return ps_parse_80211_probe(probe_frame, buf + rtap->it_len, length - rtap->it_len);
}

int
ps_parse_pcap(pcap_t *pd, struct ps_probe_frame *probe_frame)
{
	struct pcap_pkthdr	*pkt_hdr;
	const u_char		*pkt_buf;
	int			 r;

	r = pcap_next_ex(pd, &pkt_hdr, &pkt_buf);
	if (r != 1) {
		pcap_perror(pd, "pcap_next_ex");
		printf("error\n");
		return -1;
	}

	probe_frame->pcap_pkt_hdr = pkt_hdr;
	probe_frame->pcap_pkt_ptr = pkt_buf;

	// Drop incomplete packets.
	if (pkt_hdr->caplen != pkt_hdr->len)
		return 0;

	return ps_parse_radiotap(probe_frame, pkt_buf, pkt_hdr->len);
}

int
main(int argc, char *argv[])
{
	pcap_t			*pd;
	struct ps_probe_frame	 probe_frame;
	char	 		 errbuf[PCAP_ERRBUF_SIZE];
	int	 		 r;

	if (argc < 2)
		ps_usage();

	pd = pcap_open_offline(argv[1], errbuf);

	if (! pd) {
		fprintf(stderr, "%s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	for (;;) {
		bzero(&probe_frame, sizeof(probe_frame));
		r = ps_parse_pcap(pd, &probe_frame);
		if (r != 0)
			break;

		if (probe_frame.ieee80211_type != IEEE80211_FC0_TYPE_MGT &&
		    probe_frame.ieee80211_subtype != IEEE80211_FC0_SUBTYPE_PROBE_REQ)
			continue;

		if (probe_frame.invalid_frame)
			continue;

		if (strlen(probe_frame.ieee80211_nwid) == 0)
			continue;

		// XXX: we don't know how to handle fragmented probes.
		if (probe_frame.ieee80211_frag != 0)
			continue;

		printf("type: %x\n", probe_frame.ieee80211_type);
		printf("subtype: %x\n", probe_frame.ieee80211_subtype);

		printf("nwid: %s\n", probe_frame.ieee80211_nwid);

	}

	exit(EXIT_SUCCESS);
}
