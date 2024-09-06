all: serve_debug serve

serve_debug: serve.c
	gcc serve.c -o serve_debug -Wall -Wextra -O0 -ggdb

serve: serve.c
	gcc serve.c -o serve -Wall -Wextra -O2