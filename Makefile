.PHONY: all report cppcheck gcc-analyzer clang-tidy

HTTPS ?= 0

COMMON_FLAGS   = -Wall -Wextra -DHTTPS=$(HTTPS) -ggdb -rdynamic
DEBUG_FLAGS    = -O0 -ggdb #-fsanitize=address,undefined
COVERAGE_FLAGS =  -fprofile-arcs -ftest-coverage -lgcov
RELEASE_FLAGS  = -ggdb -O2 -DNDEBUG -DRELEASE

ifneq ($(HTTPS),0)
	COMMON_FLAGS += -l:libbearssl.a -I3p/BearSSL/inc -L3p/BearSSL/build
endif

all: serve_debug serve_cov serve

serve: serve.c
	gcc $< -o $@ $(COMMON_FLAGS) $(RELEASE_FLAGS)

serve_cov: serve.c
	gcc $< -o $@ $(COMMON_FLAGS) $(COVERAGE_FLAGS)

serve_debug: serve.c
	gcc $< -o $@ $(COMMON_FLAGS) $(DEBUG_FLAGS)

report: 
	lcov --capture --directory . --output-file coverage.info
	@ mkdir -p report
	genhtml coverage.info --output-directory report

cppcheck:
	cppcheck -j1 --enable=portability serve.c
	cppcheck -j1 --enable=style serve.c

gcc-analyzer:
	gcc -c -fanalyzer serve.c

clang-tidy:
	clang-tidy serve.c