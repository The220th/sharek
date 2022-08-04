CC=g++
CFLAGS=-c -Wall
LDFLAGS=-ggdb
#INCLUDE_FOLDER=-I./include/

SOURCES=sharek.cpp AES256CBC.cpp ssha256.cpp log.cpp

OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=sharek

all: $(SOURCES) $(EXECUTABLE) CLEAN

	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(INCLUDE_FOLDER) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(INCLUDE_FOLDER) $(CFLAGS) $< -o $@

CLEAN:
	find . -name "*.o" -delete