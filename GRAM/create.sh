#!/usr/bin/env bash 
# Initialize our own variables:
size=""
number=0

for i in "$@"
do
case $i in
    -s=*|--size=*)
    size="${i#*=}"
    shift # past argument=value
    ;;
    -n=*|--number=*)
    number="${i#*=}"
    shift # past argument=value
    ;;
    *)
          # unknown option
    ;;
esac
done
cp ./gram.ko /tmp/gram.ko
sudo insmod /tmp/gram.ko num_devices=$number
for i in $(seq 0 $[number-1])
do
	echo $size | sudo tee /sys/block/gram$i/disksize
done
echo "Done"
