all:
#		rm ss
		g++  ss.cpp  -L/usr/lib/mysql/ -lrt -lpcap  -pthread -lncurses  -I/usr/local/include -I/usr/local/mysql/include -L/usr/local/lib/mysql -L/usr/lib -lmysqlclient_r  -o ss -w -g3
	#	rm core*
#		g++ udpserv.cpp -ggdb -o udpserv
#all: 
	#	rm ps
#		g++  ps.cpp  -Wfatal-errors -L/usr/lib/mysql/ -lrt -lpcap  -pthread -lncurses  -I/usr/local/include -I/usr/local/mysql/include -L/usr/local/lib/mysql -L/usr/lib -lmysqlclient_r  -o ps -w -g3
	#	rm core*
a:
		rm ss.tgz
		tar -cvzf ss.tgz Makefile ss.cpp pkt.h ps.cpp
