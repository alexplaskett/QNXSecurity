
# Script to perform a quick and dirty device review of QNX (BB10 device)
# Produces a lot of output so devrev.sh > outfile.txt
# al3x 2015 
# To add, files writable by current user. 

PATH=/proc/boot:/base/bin:/base/usr/bin

echo "++ Version Info ++ "
uname -a

echo "++ CPU Info ++"
cat /proc/cpuinfo

echo "++ File System Mounts ++ "
mount 

echo "++ Processes by user ++ "
pidin U

echo "++ Proceses by path and args ++"
pidin A

echo "++ Process Environment ++"
pidin -f E

echo "++ Connection IDs and file descriptors associated with the process ++"
pidin -f o

echo "++ Attempting UID/GID leak bug ++ "
/base/sbin/sysctl qnx.kern.nws.table

echo "++ General sysctls ++"
/base/sbin/sysctl -a

# None (/base/usr/bin/find on Android)
echo "++ setuid root binaries ++"
find / -user root -perm -4000 -print

# Finds setuid nobody only :(
echo "++ Setuid Binaries ++"
find / -type f \( -perm -4000 -o -perm -2000 \)

echo "++ World Writable Files ++"
find / -perm -2 ! -type l -ls

echo "++ World readable files ++"
find / -perm -1 ! -type l -ls

echo "++ World readable conf files ++"
find / -perm -1 ! -type l -ls | grep "conf"

echo "++ World writable conf files ++"
find / -perm -2 ! -type l -ls | grep "conf"

echo "++ DEV FS listing ++"
ls -alR /dev/

echo "++ Testing symlinks ++"
ln -s devrev.sh t
echo $?

echo "++ Testing pathmgr symlink ++"
ln -sP /dev/shmem test

echo "++ QNX config"
/proc/boot/getconf -a

echo "++ Listerning sockets ++"
netstat -a

echo "++ IPC endpoints ++"
ls -al /dev/name/local

# PPS security
echo '\n################################\nPPS OBJECTS\n################################\n'
for pps in $(/usr/bin/find /pps -not -type d -not -name control -size +3c); do
	echo "\n==========\npps object: ${pps}\n==========\n"
	cat ${pps}
done

echo "++ PPS files with write access ++"
echo "++ control objects are interesting ++"
dir="/pps"
files="$(/usr/bin/find "$dir" -type f)"
echo "Count: $(echo -n "$files" | /usr/bin/wc -l)"
echo "$files" | while read file; do
	if [ -w "$file" ]
	then
   		echo "Write permission is granted on $file"
	fi
done