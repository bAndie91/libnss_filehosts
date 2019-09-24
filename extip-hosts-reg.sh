if [ -n "$currentip" ]
then
	echo "Register host extip.localhost = $currentip" >&2
	if grep -qE '^\S+\s+extip.localhost' /etc/hosts
	then
		sed -e "s/^\S\+\s\+extip\.localhost\s*$/$currentip extip.localhost/" -i /etc/hosts
	else
		echo "$currentip extip.localhost" >>/etc/hosts
	fi
else
	exit 1
fi
