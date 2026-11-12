CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LIBS = -lcrypto

# `make` builds the v1 lock and hub, plus the instance generator you run once
# to create your own instance.txt from your roll number.
all: lock_server hub_client instance_generator

lock_server: lock_server.cpp slink.hpp pki.hpp
	$(CXX) $(CXXFLAGS) lock_server.cpp -o lock_server $(LIBS)
hub_client: hub_client.cpp slink.hpp
	$(CXX) $(CXXFLAGS) hub_client.cpp -o hub_client $(LIBS)
instance_generator: instance_generator.cpp secrets.hpp slink.hpp
	$(CXX) $(CXXFLAGS) instance_generator.cpp -o instance_generator $(LIBS)

clean:
	rm -f lock_server hub_client instance_generator

.PHONY: all clean
