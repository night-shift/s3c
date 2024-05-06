lib_name      = s3c
lib_files     = src/s3c.c
test_files    = tests/main.c
exmaple_files = examples/usage.c
out_dir       = bin
link_libs     = -lssl -lcrypto
CFLAGS        = -std=c99 -Wall -Wextra -Wcast-align -pedantic -fPIC

debug_on      = 0
valgrind_on   = 0

ifeq ($(debug_on), 1)
	CFLAGS += -g -O0 -DDEBUG -MMD -MP
	out_dir := $(out_dir)/debug
else
	CFLAGS += -O2 -Werror
endif

cache        = $(out_dir)/cache
lib          = $(out_dir)/lib$(lib_name)

lib_objs     = $(patsubst %.c,$(cache)/%.o, $(lib_files))
test_objs    = $(patsubst %.c,$(cache)/%.o, $(test_files))
example_objs = $(patsubst %.c,$(cache)/%.o, $(exmaple_files))

.DEFAULT_GOAL := static

print:
	@echo "building $(out_dir)/$(lib_name) with...\n\t$(CC) $(CFLAGS)"

static: print $(lib).a

tests: print $(lib).a $(test_objs)
	@$(CC) $(CCFLAGS) -o $(out_dir)/tests $(test_objs) $(lib).a $(link_libs)
	@echo "running tests..."
	@if [ $(valgrind_on) = 1 ];\
	then\
        valgrind -s --leak-check=full --track-origins=yes $(out_dir)/tests; \
	else\
        ./$(out_dir)/tests; \
    fi
	@echo "...complete."

examples: print $(lib).a $(example_objs)
	@$(CC) $(CCFLAGS) -o $(out_dir)/usage $(example_objs) $(lib).a $(link_libs)

clean:
	@rm -r -f $(out_dir)
	@echo "clean"

$(lib).a: $(lib_objs)
	@echo "\tpacking $(lib).a"
	@$(AR) rcs $(lib).a $(lib_objs)

$(cache)/%.o: %.c
	@echo "\tcompile $@"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $< -c -o $@

-include $(lib_objs:%.o=%.d) $(test_objs:%.o=%.d)

.PHONY: clean print
