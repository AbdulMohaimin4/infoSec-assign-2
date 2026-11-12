# SmartLock v2 build. You implement securelink2.cpp; everything else is provided.
#   make            build the v2 lock and hub against your securelink2.cpp
#   make clean
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall
LDLIBS   ?= -lcrypto

APPS = lock_server2 hub_client2

all: $(APPS)

lock_server2: lock_server2.cpp securelink2.cpp securelink2.hpp dh2048.hpp pki.hpp slink.hpp
	$(CXX) $(CXXFLAGS) -o $@ lock_server2.cpp securelink2.cpp $(LDLIBS)

hub_client2: hub_client2.cpp securelink2.cpp securelink2.hpp dh2048.hpp pki.hpp slink.hpp
	$(CXX) $(CXXFLAGS) -o $@ hub_client2.cpp securelink2.cpp $(LDLIBS)

clean:
	rm -f $(APPS)

.PHONY: all clean
