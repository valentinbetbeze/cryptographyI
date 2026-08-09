.PHONY: build build-dbg test clean format

all: build

build:
	cmake --preset gcc-release
	cmake --build --preset gcc-release

build-dbg:
	cmake --preset gcc-debug
	cmake --build --preset gcc-debug

test:
	@if [ "$$(uname -s)" = "Linux" ]; then \
		cmake --preset gcc-sanitize && \
		cmake --build --preset gcc-sanitize && \
		ctest --preset gcc-test-sanitize; \
	else \
		echo "Skipping mandatory sanitizer test pass: unsupported on $$(uname -s) (LeakSanitizer requires Linux)." && \
		@make build && \
		ctest --preset gcc-test; \
	fi

format:
	find . -type f \( -name '*.c' -o -name '*.h' \) -exec clang-format -i {} \;

clean:
	rm -rf build
