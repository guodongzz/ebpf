#include "../../../testdata/common.h"

char __license[] __section("license") = "MIT";

struct bpf_map_def map1 __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = 4,
	.value_size  = 4,
	.max_entries = 1,
};

enum e { HOOPY, FROOD };

typedef long long int longint;

typedef struct {
	longint bar;
	_Bool baz;
	enum e boo;
} barfoo;

volatile const enum e my_constant = FROOD;

volatile const barfoo struct_const;

__section("socket") int filter() {
	return my_constant + struct_const.bar;
}
