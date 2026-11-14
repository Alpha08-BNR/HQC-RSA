CXX = g++
CXXFLAGS = -O2 -std=c++17 -Wall
LDLIBS = -lcrypto

all: server client

server: server.cpp hqc_common.hpp
	$(CXX) $(CXXFLAGS) -o $@ server.cpp $(LDLIBS)

client: client.cpp hqc_common.hpp
	$(CXX) $(CXXFLAGS) -o $@ client.cpp $(LDLIBS)

clean:
	rm -f server client

.PHONY: all clean
