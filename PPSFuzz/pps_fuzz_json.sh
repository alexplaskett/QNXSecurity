while true
do
	./radamsa base.txt > fuzzed_json.txt
	./PPSJSON fuzzed_json.txt
	test $? -gt 127 && break
done