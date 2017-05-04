#!/bin/bash

	sudo apt-get install build-essential libtool autotools-dev automake pkg-config bsdmainutils curl

    sudo apt-get install g++-mingw-w64-i686 mingw-w64-i686-dev 
	cd ..
	cd depends
    make HOST=i686-w64-mingw32 -j 8

	cd sources
	if test -f "libsodium-1.0.8-mingw.tar.gz"; then
  		echo libsodium-1.0.8-mingw.tar.gz: yes; 
	else
		wget  https://download.libsodium.org/libsodium/releases/old/libsodium-1.0.8-mingw.tar.gz;
	fi
	tar -xvzf libsodium-1.0.8-mingw.tar.gz  libsodium-win32

	cp -a libsodium-win32/* ./../x86_64-w64-mingw32
	rm -rf libsodium-win32 
	cd ..
	cd ..
	./autogen.sh
	CONFIG_SITE=$PWD/depends/i686-w64-mingw32/share/config.site ./configure --prefix=/ --disable-tests
	make -j 8 		
exit 0
