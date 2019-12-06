CXX=g++
#CXXFLAGS=--std=c++11 -g $(INC) -pedantic
CXXFLAGS=--std=c++11 -pthread -g $(INC)
INC = -I./ -I$(cpath)/include
LIBPATH = -L$(cpath)/lib -L$(npath)/lib
LIB = -lnghttp2 -lcurl -lz -lssl -lcrypto
BIN=clientSimulator

SRC=$(wildcard *.cc)

all:
	@echo $(value TEST)
	$(CXX) $(CXXFLAGS) $(LIBPATH) $(SRC) $(LIB) -o $(BIN)

clean:
	rm -f *.o $(BIN)
