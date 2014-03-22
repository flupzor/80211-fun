from ctypes import *
from ctypes.util import find_library

import os

PROJECT_DIR=os.path.dirname(os.path.realpath(__file__))
ps = CDLL(os.path.join(PROJECT_DIR,"probescan.so"))

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

	def __init__(self, addr1, addr2, addr3):
		self.addr1 = addr1
		self.addr2 = addr2
		self.addr3 = addr3

	def __repr__(self):
		return "{0} {1} {2}".format(
			self.addr1,
			self.addr2,
			self.addr3,
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
			)

			yield probeframe

			r = ps_next()
		
def main():
	for probeframe in ProbeFrame.scan("/home/alex/dump-20-feb-2014-3.pcap"):
		print probeframe

if __name__ == "__main__":
	main()
