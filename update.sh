#!/bin/sh

# first parameter is a current directory, where wallet is executing now (directory, which we should update)
# second parameter is a update directory which contains unpacked jar for update
# third parameter is a boolean flag, which indicates desktop mode

echo Updater started
chmod -v 755 ./update1.sh
echo "Starting update1.sh in detached process..."
echo nohup ./update1.sh $1 $2 $3 

nohup ./update1.sh $1 $2 $3 &
