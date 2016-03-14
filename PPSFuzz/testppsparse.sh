# ppsparse() testers
while true
do
   ./radamsa pps_base.txt > fuzzed.txt
   value=`cat fuzzed.txt`
   ./PPS "$value"
   test $? -gt 127 && break
done

# Other example

while true
do
	./radamsa base_nav.txt > fuzzed.txt && cat fuzzed.txt > /pps/system/navigator/background
done



