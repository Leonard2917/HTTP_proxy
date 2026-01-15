CXX = g++
CXXFLAGS = -std=c++17 -pthread -Wall -O2
TARGET = proxy_engine
SRCS = main.cpp server.cpp proxy_handler.cpp settings.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)
