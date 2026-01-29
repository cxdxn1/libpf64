cc = clang
lib_dir = $(wildcard lib/*.c)
include_dir = -Ilib
lib = libpf64.a

all: $(lib)

$(lib):
	$(cc) -g $(include_dir) -c $(lib_dir)
	ar rcs $(lib) *.o
	rm -f *.o

clean:
	rm -f $(lib) *.o

.PHONY: all clean
