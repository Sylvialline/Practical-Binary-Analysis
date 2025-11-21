#!/bin/bash

host=`hostname`
dir=`pwd`
if [[ "$host" == "binary-VirtualBox" ]]
then
  echo -n "Setting wallpaper... "
  gsettings set org.gnome.desktop.background picture-uri "$dir/wall_1024x768.jpg"
  echo "Done!"
else
  echo "You'll need to manually set the wallpaper on this platform"
fi

