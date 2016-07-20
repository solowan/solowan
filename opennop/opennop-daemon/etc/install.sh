#!/bin/bash

# move to the directory where the script is located
CDIR=`dirname $0`
cd $CDIR
CDIR=$(pwd)


while getopts "y" opt; do
    case "$opt" in
        y)
            OVERWRITE="yes" 
            echo "Overwrite option selected"
            ;;
	*)  echo "--"
            echo "-- ERROR: option unknown"
            echo "--"
            exit 1 
            ;;
    esac
done

# Copy system V init service script
cp init.d/solowan /etc/init.d
chmod +x /etc/init.d/solowan 

mkdir -p /etc/opennop

# Copy opennop-delflows.sh always
cp opennop/opennop-delflows.sh /etc/opennop
chmod +x /etc/opennop/opennop-delflows.sh

# Copy opennop-addflows.sh 
if [ -f /etc/opennop/opennop-addflows.sh ]; then
    if [ "$OVERWRITE" ]; then
        echo "Overwriting /etc/opennop/opennop-addflows.sh file (original file moved to opennop-addflows.sh.bak)"
        mv -v /etc/opennop/opennop-addflows.sh /etc/opennop/opennop-addflows.sh.bak
        cp -v opennop/opennop-addflows.sh /etc/opennop
        chmod +x /etc/opennop/opennop-addflows.sh
    else
        echo "/etc/opennop/opennop-addflows.sh already exists: NOT ovewritting (select -y option to overwrite)"
    fi
else
    echo "Copying /etc/opennop/opennop-addflows.sh file"
    cp -v opennop/opennop-addflows.sh /etc/opennop
    chmod +x /etc/opennop/opennop-addflows.sh
fi

# Copy opennop.conf file
if [ -f /etc/opennop/opennop.conf ]; then
    if [ "$OVERWRITE" ]; then
        echo "Overwriting /etc/opennop/opennop.conf file (original file moved to opennop.conf.bak)"
        mv -v /etc/opennop/opennop.conf /etc/opennop/opennop.conf.bak
        cp -v opennop/opennop.conf /etc/opennop
    else
        echo "/etc/opennop/opennop.conf already exists: NOT ovewritting (select -y option to overwrite)"
    fi
else
    echo "Copying /etc/opennop/opennop.conf file"
    cp -v opennop/opennop.conf /etc/opennop
fi

# Copy log4crc file
if [ -f /etc/opennop/log4crc ]; then
    if [ "$OVERWRITE" ]; then
        echo "Overwriting /etc/opennop/log4crc file (original file moved to log4crc.bak)"
        mv -v /etc/opennop/log4crc /etc/opennop/log4crc.bak
        cp -v opennop/log4crc /etc/opennop/log4crc
    else
        echo "/etc/opennop/log4crc already exists: NOT ovewritting (select -y option to overwrite)"
    fi
else
    echo "Copying /etc/opennop/log4crc file"
    cp -v opennop/log4crc /etc/opennop
fi
