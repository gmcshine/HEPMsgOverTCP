#!/usr/bin/bash
echo "Simulater 40 TAP_P_AGENT Process to send HEP message simultaneously"
#each process runs with 2 threads
for ((i=1; i<=40; i++))
do
    # 2600 msg / second on each process
    #./hepSender -mn 1300 -rn 400 -tn 2 & 
    #./hepSender -mn 650 -rn 800 -tn 4 & 
    #./hepSender -mn 2600 -rn 200 & 
    
     ./hepSender -mn 6500 -rn 400 -tn 4 & 
done

for pid in $(jobs -p) 
do
    wait $pid
done

echo "All background jobs Done!!!"
