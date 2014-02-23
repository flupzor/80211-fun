probescan: probescan.c
	cc -o probescan -lpcap probescan.c
test: probescan
	probescan ../dump-20-feb-2014-3.pcap
