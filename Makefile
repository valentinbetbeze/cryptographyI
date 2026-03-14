.PHONY: build test clean format

all: build

build:
	cmake --preset gcc-release
	cmake --build --preset gcc-release

build-dbg:
	cmake --preset gcc-debug
	cmake --build --preset gcc-debug

test:
	ctest --preset gcc-test

format:
	find . -type f \( -name '*.c' -o -name '*.h' \) -exec clang-format -i {} \;

clean:
	rm -rf build
