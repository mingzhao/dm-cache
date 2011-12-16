include makeinclude

OBJ	= main.o

all: cachetest

cachetest: $(OBJ)
	$(LD) $(LDFLAGS) -o cachetest $(OBJ) $(LIBS)

clean:
	rm -f *.o
	rm -f cachetest

allclean: clean
	rm -f makeinclude configure.paths platform.h
	
install: all
	./makeinstall

makeinclude:
	@echo please run ./configure
	@false

SUFFIXES: .cpp .o
.cpp.o:
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $<
