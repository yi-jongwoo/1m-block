all: 1m-block

1m-block : main.o proto_structures.o
	g++ -o 1m-block main.o proto_structures.o -lnetfilter_queue

proto_structures.o : proto_structures.cpp proto_structures.h
	g++ -c -o proto_structures.o proto_structures.cpp
main.o : main.cpp proto_structures.h
	g++ -c -o main.o main.cpp -Wno-multichar

clean :
	rm -f *.tmp.bin
	rm -f *.o
	rm -f 1m-block
