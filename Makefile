probescan: probescan.c
	cc -o probescan -lpcap probescan.c
sharedlib:
	cc -c -fpic probescan.c
	cc -lpcap -shared -o probescan.so probescan.o
