LDLIBS=-lpcap

all: airodump

airodump: mac.o airodump.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o
