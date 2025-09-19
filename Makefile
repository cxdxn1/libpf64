cc = clang
src_dir = $(wildcard src/*.c)
include_dir = -Iinclude
lib = libpf64.a

all: $(lib)

$(lib):
	$(cc) -g -c $(include_dir) $(src_dir)
	ar rcs $(lib) *.o
	rm -f *.o

clean:
	rm -f $(lib) *.o

.PHONY: all clean
