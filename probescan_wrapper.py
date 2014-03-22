#
# Copyright (c) 2014 Alexander Schrijver <alex@flupzor.nl>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

from ctypes import *
from ctypes.util import find_library

from datetime import datetime, timedelta

import os

PROJECT_DIR=os.path.dirname(os.path.realpath(__file__))
ps = CDLL(os.path.join(PROJECT_DIR,"probescan.so"))

class BPFTimeval(Structure):
    _fields_ = [("tv_sec", c_uint32 ), ("tv_usec", c_uint32)]

    def __repr__(self):
        return "{0}.{1}".format(self.tv_sec, self.tv_usec)

    def to_datetime(self):
        return datetime.fromtimestamp(self.tv_sec) + timedelta(microseconds=self.tv_usec)

" Declarations "

ps_open = ps.ps_open
ps_next = ps.ps_next

ps_80211_type = ps.ps_80211_type
ps_80211_type.restype = c_uint8

ps_80211_subtype = ps.ps_80211_subtype
ps_80211_subtype.restype = c_uint8

ps_80211_addr1 = ps.ps_80211_addr1
ps_80211_addr1.restype = c_char_p

ps_80211_addr2 = ps.ps_80211_addr2
ps_80211_addr2.restype = c_char_p

ps_80211_addr3 = ps.ps_80211_addr3
ps_80211_addr3.restype = c_char_p

ps_80211_invalid_frame = ps.ps_80211_invalid_frame

ps_80211_frag = ps.ps_80211_frag

ps_80211_nwid = ps.ps_80211_nwid
ps_80211_nwid.restype = c_char_p

ps_80211_timeval = ps.ps_80211_timeval
ps_80211_timeval.restype = BPFTimeval

class IEEE80211(object):
	IEEE80211_FC0_VERSION_MASK=0x03
	IEEE80211_FC0_VERSION_SHIFT=0
	IEEE80211_FC0_VERSION_0=0x00
	IEEE80211_FC0_TYPE_MASK=0x0c
	IEEE80211_FC0_TYPE_SHIFT=2
	IEEE80211_FC0_TYPE_MGT=0x00
	IEEE80211_FC0_TYPE_CTL=0x04
	IEEE80211_FC0_TYPE_DATA=0x08

	IEEE80211_FC0_SUBTYPE_PROBE_REQ=0x40


class ProbeFrame(IEEE80211):

	def __init__(self, addr1, addr2, addr3, nwid, timeval):
		self.addr1 = addr1
		self.addr2 = addr2
		self.addr3 = addr3
		self.nwid = nwid
		self.timeval = timeval

	def __repr__(self):
		return "{0} {1} {2} {3} {4}".format(
			self.addr1,
			self.addr2,
			self.addr3,
			self.nwid,
			self.timeval,
			self.timeval.to_datetime(),
		)

	@classmethod
	def scan(cls, filename):
		r = ps_open(filename)
		if r == -1:
			return

		r = ps_next()
		while r == 0:
			if ps_80211_type() != cls.IEEE80211_FC0_TYPE_MGT or \
				ps_80211_subtype() != cls.IEEE80211_FC0_SUBTYPE_PROBE_REQ:

				r = ps_next()
				continue

			if ps_80211_invalid_frame():
				r = ps_next()
				continue

			if ps_80211_frag():
				r = ps_next()
				continue

			probeframe = ProbeFrame(
				ps_80211_addr1(),
				ps_80211_addr2(),
				ps_80211_addr3(),
				ps_80211_nwid(),
				ps_80211_timeval(),
			)

			yield probeframe

			r = ps_next()
		
def main():
	for probeframe in ProbeFrame.scan("/home/alex/dump-20-feb-2014-3.pcap"):
		print probeframe

if __name__ == "__main__":
	main()
