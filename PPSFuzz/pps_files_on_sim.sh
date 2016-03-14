

# Script to test writable files:

FILES="$(find /pps -type f)"

for f in ${FILES[@]}
do

#echo "test" >> $f

[ -w $f ] && echo $f
#if [ $? -eq 0 ]; then
#       #echo "test"
#fi

done

