probescan: probescan.c
	cc -o probescan -lpcap probescan.c
sharedlib:
	cc -c -fpic probescan.c
	cc -lpcap -shared -o probescan.so probescan.o
test: probescan
	probescan /home/alex/dump-20-feb-2014-3.pcap | python -u parse.py > parse.log
