mig="windows-2022-core"

joined=0
size=$(gcloud compute instance-groups managed describe $mig --format="value(targetSize)")

for instance in $(gcloud compute instance-groups managed list-instances $mig --format="value(instance)"); do  
    isJoined=$(grep -q 'Successfully registered computer account.' <<< $(gcloud compute instances get-serial-port-output $instance 2>/dev/null); echo $?)

    if [ "$isJoined" == "0" ]; then
        ((joined=joined+1))
        echo "$instance: 1"
    else
        echo "$instance: 0"
    fi
done

echo "Joined $joined of $size"