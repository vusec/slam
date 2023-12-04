cores=$1
folder=$2
targets=$3
binary=$4

if [ -z "$4" ]
  then
    echo "Usage: ./$(basename -- "$0") <cores> <output_folder> <targets> <binary>"
    exit
fi

mkdir -p $folder

split -l $(( ($(cat ${targets} | wc -l) + $cores - 1)/$cores )) ${targets} part -da 3


for i in $(seq -f "%03g" 0 `expr $cores - 1`); do
    echo "Starting thread" $i
    ./run_single.sh part${i} $binary 2>&1 > ${folder}/log${i}.txt & 
done
