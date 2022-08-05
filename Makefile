CC=g++
CFLAGS=-c -Wall -O2
LDFLAGS=-O2
#LDFLAGS=-ggdb
#INCLUDE_FOLDER=-I./include/

SOURCES=sharek.cpp AES256CBC.cpp ssha256.cpp log.cpp

OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=sharek

all: $(SOURCES) $(EXECUTABLE) CLEAN

	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

CLEAN:
	find . -name "*.o" -delete