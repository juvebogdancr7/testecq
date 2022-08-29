CFLAGS=-c -g -O0 -Wextra -Wall -pedantic -std=gnu99 `pkg-config --cflags openssl`
LDFLAGS=`pkg-config --libs openssl`
SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
EXEC=ecqv
CC=gcc

all: $(SOURCES) $(EXEC)

$(EXEC): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o $(EXEC)


# CFLAGS=-c -g -O0 -Wextra -Wall -pedantic -std=gnu99 -lwolfssl
# LDFLAGS=-lwolfssl
# SOURCES=$(wildcard *.c)
# OBJECTS=$(SOURCES:.c=.o)
# EXEC=ecqv
# CC=gcc

# all: $(SOURCES) $(EXEC)

# $(EXEC): $(OBJECTS)
# 	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

# .c.o:
# 	$(CC) $(CFLAGS) $< -o $@

# clean:
# 	rm -f *.o $(EXEC)
