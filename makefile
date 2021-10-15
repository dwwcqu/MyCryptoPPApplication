INCLUDE = include/
SCR = scr/
LINKER = -L/usr/local/lib/ -lcryptopp
OBJ = obj/encodeAndDecode.o

main: $(OBJ) main.cpp
	$(/bin/bash /scr/make.sh)
	g++ main.cpp $(OBJ) -o main $(LINKER)