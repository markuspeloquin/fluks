#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "serpent_bits.h"

#define MAX_OPS 25
#define MAX_VALS (MAX_OPS + 1)

enum op_type { OP_BEGIN=0, OP_XOR=0, OP_AND, OP_OR, OP_NOT, OP_END };
/* number of arguments of each op_type
 * (op_type(i) takes OP_ARGS[i] arguments)*/
uint8_t OP_ARGS[] = { 2, 2, 2, 1, 0 };

struct op {
	enum op_type	type;

	/* indices of the operand temporaries (in vals); if type==OP_NOT,
	 * j ignored; else, i<j */
	uint8_t		i;
	uint8_t		j;
};

struct op_chain {
	struct op	ops[MAX_OPS];
	/* y_i's should be equal to the temporary corresponding to
	 * column indices[i] in vals; put differently, vals contains all
	 * intermediate and final values, and indices[i] is the index into
	 * vals of the final value y_i */
	uint8_t		indices[4];
	/* the number of operations that will remain unchanged as they
	 * produced a final y_i value */
	uint8_t		hold;
	/* the number of operations that currently are used; whenever a final
	 * y_i value is found, hold==sz */
	uint8_t		sz;

	/* computed values for this configuration */
	uint8_t		vals[16][MAX_VALS];
	bool		dirty[MAX_VALS];
};

static void
op_chain_init(struct op_chain *seq)
{
	uint8_t	i;

	for (i = 0; i < MAX_OPS; i++) {
		seq->ops[i].type = OP_BEGIN;
		seq->ops[i].i = 0;
		seq->ops[i].j = 1;
	}
	for (i = 0; i < 4; i++)
		seq->indices[i] = MAX_VALS;

	seq->hold = 0;
	seq->sz = 1;

	for (i = 0; i < 16; i++) {
		seq->vals[i][0] = (i & 0x8) != 0;
		seq->vals[i][1] = (i & 0x4) != 0;
		seq->vals[i][2] = (i & 0x2) != 0;
		seq->vals[i][3] = i & 0x1;
	}
	for (i = 0; i < MAX_VALS; i++)
		seq->dirty[i] = i >= 4;
}

/* advance if possible; if cannot, return false, leave i,j=0 and type=XOR */
static bool
op_advance(struct op_chain *seq, uint8_t which_op)
{
	struct op	*op = seq->ops + which_op;
	bool		push_type = false;

	/* advance indices */
	if (OP_ARGS[op->type] == 1) {
		/* advance i */
		if (++op->i == which_op + 4) {
			/* i cannot advance; reset the only used index */
			op->i = 0;
			push_type = true;
		}
	} else {
		/* advance j */
		if (++op->j == which_op + 4) {
			/* j cannot advance; advance i */
			op->j = ++op->i + 1;
			if (op->j == which_op + 4) {
				/* i cannot advance; reset the used indices */
				op->i = 0;
				op->j = 1;
				push_type = true;
			}
		}
	}

	/* this op was changed */
	seq->dirty[which_op + 4] = true;

	if (push_type) {
		/* advance the operator */
		if (++op->type == OP_END) {
			/* cannot advance the operator */
			op->type = OP_BEGIN;
			return false;
		}
	}

	return true;
}

static void
op_chain_advance(struct op_chain *seq)
{
	uint8_t	i = seq->sz;

	while (i > seq->hold) {
		/* advance last op */
		if (op_advance(seq, i - 1))
			break;

		i--;
	}
	if (i != seq->hold) return;

	/* cannot advance the existing operators any more; add an operator  */
	seq->sz++;
}

static inline void
run_chain(struct op_chain *seq)
{
	/* for each operation */
	for (uint8_t i = 0; i < seq->sz; i++) {
		if (!seq->dirty[i+4]) continue;
		seq->dirty[i+4] = false;

		register const struct op *op = seq->ops + i;

		/* for each input value */
		for (uint8_t j = 0; j < 16; j++) {
			register uint8_t	r;

			switch (op->type) {
			case OP_XOR:
				r = seq->vals[j][op->i] ^ seq->vals[j][op->j];
				break;
			case OP_AND:
				r = seq->vals[j][op->i] & seq->vals[j][op->j];
				break;
			case OP_OR:
				r = seq->vals[j][op->i] | seq->vals[j][op->j];
				break;
			case OP_NOT:
				r = ~seq->vals[j][op->i];
				break;
			default:
				assert(0);
			}
			seq->vals[j][i+4] = r;
		}
	}
}

static void
print_var(FILE *out, bool in, uint8_t i)
{
	if (i < 4)
		fprintf(out, "%c%hhu", in?'x':'y', i);
	else
		fprintf(out, "t%hhu", i - 4);
}

void
print_chain(FILE *out, const struct op_chain *seq)
{
	fprintf(out, "\tregister uint32_t ");
	for (uint8_t i = 0; i < seq->sz; i++) {
		fprintf(out, "%st%hhu", i ? ", " : "", i);
	}
	fprintf(out, ";\n");
	for (uint8_t i = 0; i < seq->sz; i++) {
		char	type = '\0';

		switch (seq->ops[i].type) {
		case OP_XOR:
			type = '^';
			break;
		case OP_AND:
			type = '&';
			break;
		case OP_OR:
			type = '|';
			break;
		case OP_NOT:
			type = '~';
			break;
		default:
			assert(0);
		}

		fprintf(out, "\tt%hhu = ", i);
		switch(OP_ARGS[seq->ops[i].type]) {
		case 1:
			fprintf(out, "%c", type);
			print_var(out, true, seq->ops[i].i);
			break;
		case 2:
			print_var(out, true, seq->ops[i].i);
			fprintf(out, " %c ", type);
			print_var(out, true, seq->ops[i].j);
			break;
		default:
			assert(0);
		}
		fprintf(out, ";\n");
	}

	for (uint8_t i = 0; i < 4; i++) {
		fprintf(out, "\ty%hhu = ", i);
		print_var(out, false, seq->indices[i]);
		fprintf(out, ";\n");
	}
}

void
brute_sbox(uint8_t sboxnum, bool inverse, struct op_chain *out_seq)
{
	/* all outputs */
	uint8_t		y[16][4];

	struct op_chain	seq;
	uint8_t		i;
	uint8_t		found;
	uint8_t		last_len;

	op_chain_init(&seq);

	/* precompute results of sbox cumputations using slow method */
	for (i = 0; i < 16; i++) {
		uint32_t	x0[4];
		uint32_t	y0[4];

		for (uint8_t j = 0; j < 4; j++)
			x0[j] = seq.vals[i][j];

		if (inverse)
			sbox_inv(sboxnum, x0, y0);
		else
			sbox(sboxnum, x0, y0);

		y[i][0] = y0[0] & 0xff;
		y[i][1] = y0[1] & 0xff;
		y[i][2] = y0[2] & 0xff;
		y[i][3] = y0[3] & 0xff;
	}

	last_len = 1;
	found = 0;

	for (;;) {
		if (seq.sz != last_len) {
			last_len = seq.sz;
			printf("sz %hhu\n", last_len);
		}

		/* for this guess, compute the values of each temporary
		 * that has changed */
		run_chain(&seq);

		/* for each column in y[], find a column in vals[] that
		 * matches */
		for (i = 0; i < 4; i++) {
			uint8_t	j;
			bool	match;

			/* already found */
			if (seq.indices[i] < MAX_VALS) continue;

			/* check only the last column of vals[]; all
			 * possible permutations of the previous columns
			 * have already been seen and yielded no fruits */
			j = seq.sz + 3;

			/* check each number in the column with y */
			match = true;
			for (uint8_t k = 0; k < 16; k++) {
				if (y[k][i] != seq.vals[k][j]) {
					match = false;
					break;
				}
			}
			if (match) {
				seq.indices[i] = j;
				seq.hold = seq.sz;
				found++;
				printf("partial match for %hhu\n", i);
				print_chain(stdout, &seq);
				break;
			}
		}

		if (found == 4) break;
		op_chain_advance(&seq);
	}

	memcpy(out_seq, &seq, sizeof(seq));
}

void
print_function(FILE *out, uint8_t sbox, bool inverse,
    const struct op_chain *seq)
{
	fprintf(out,
"inline void\n"
"sbox_%hhu%s(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,\n"
"    uint32_t &y0, uint32_t &y1, uint32_t &y2, uint32_t &y3)\n"
"{\n",
	    sbox, inverse ? "_inv" : "");

	print_chain(out, seq);

	fprintf(out,
"}\n"
	    );
}

int
main(int argc, char **argv)
{
	struct	op_chain	seq;
	char			path[80];
	long			tlong;
	char			*end;
	FILE			*out;
	uint8_t			sbox;
	bool			inverse;

	if (argc != 3) {
		printf(
		    "usage: %s NUM0 NUM1\n\n"
		    "NUM0 - S-box number in [0,7]\n"
		    "NUM1 - 0: non-inverse, 1: inverse\n",
		    *argv);
		return 1;
	}

	errno = 0;
	tlong = strtol(argv[1], &end, 10);
	if (errno || *end != '\0') {
		fprintf(stderr, "%s: not a number: %s\n", *argv, argv[1]);
		return 1;
	}
	if (tlong < 0 || tlong > 7) {
		fprintf(stderr, "%s: S-box number outside range\n", *argv);
		return 1;
	}
	sbox = tlong;

	tlong = strtol(argv[2], &end, 10);
	if (errno || *end != '\0') {
		fprintf(stderr, "%s: not a number: %s\n", *argv, argv[2]);
		return 1;
	}
	if (tlong != 0 && tlong != 1) {
		fprintf(stderr, "%s: bad inverse type\n", *argv);
		return 1;
	}
	inverse = tlong;

	sprintf(path, "sbox_%hhu%s.cpp", sbox, inverse ? "_inv" : "");
	if (!(out = fopen(path, "w"))) {
		fprintf(stderr,
		    "%s: failed to open file in write mode\n", *argv);
		return 1;
	}

	printf("starting sbox=%hhu inverse=%s\n", sbox,
	    inverse ? "true" : "false");

	brute_sbox(sbox, inverse, &seq);
	print_function(stdout, sbox, inverse, &seq);
	print_function(out, sbox, inverse, &seq);

	return 0;
}
