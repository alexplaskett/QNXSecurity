while true
do
	./radamsa pps_base.txt > fuzzed_pps.txt
	./PPSJSON fuzzed_pps.txt
	test $? -gt 127 && break
done