echo "aa"   > /data/local/tmp/aa
for port in `seq 50000 51000`;
do
        nc -v 47.92.141.202 $port < /data/local/tmp/aa &
done
exit 0

