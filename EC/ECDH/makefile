SRC=$(wildcard *.cpp)
OBJS=$(patsubst %.cpp,%.o,$(SRC) )
TARGET=test
CPPFLAGS= -g -I/usr/local/include
LIBS=-lpthread -L/usr/local/lib -lcrypto
$(TARGET):$(OBJS)
	g++  $+ -o $@ $(LIBS)

