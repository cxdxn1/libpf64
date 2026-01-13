cc = clang
lib_dir = $(wildcard lib/*.c)
include_dir = -Iinclude
lib = libpf64.a

all: $(lib)

$(lib):
	$(cc) -g -c $(include_dir) $(lib_dir)
	ar rcs $(lib) *.o
	rm -f *.o

clean:
	rm -f $(lib) *.o

.PHONY: all clean
