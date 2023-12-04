targets=$1
binary=$2

if [ -z "$2" ]
  then
    echo "Usage: ./$(basename -- "$0") <targets> <binary>"
    exit
fi

echo "Targets: " $targets

counter=0
total=`cat ${targets}  | wc -l`

cat ${targets} | while read line
do
    counter=$((counter+1))
    addr=`echo $line | awk '{print $1}'`
    name=`echo $line | awk '{print $2}'`
    echo "[INFO] Queue ${counter}/${total}"
    timeout 60s python3 ../scanner/main.py -p ${binary} -a 0x${addr} -n ${name} 2>&1
done
