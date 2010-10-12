#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "serpent_bits.h"
#include "thread_list.h"

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
	/* successive 'hold' values */
	uint8_t		hold_vals[4];
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

	/* 'zero' out */
	for (i = 0; i < MAX_OPS; i++) {
		seq->ops[i].type = OP_BEGIN;
		seq->ops[i].i = 0;
		seq->ops[i].j = 1;
	}
	for (i = 0; i < 4; i++) {
		seq->indices[i] = MAX_VALS;
		seq->hold_vals[i] = 0;
	}

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

static bool
op_ordered(const struct op *a, const struct op *b)
{
	/* 0: smallest, 1: largest */
	uint8_t a0 = a->i;
	uint8_t a1 = OP_ARGS[a->type] == 1 ? a0 : a->j;
	uint8_t b0 = b->i;
	uint8_t b1 = OP_ARGS[b->type] == 1 ? b0 : b->j;

	/* if b has a value after both of a's values, b comes after */
	if (b1 > a1) return true;

	/* from here on out, no other comparison matters except to provide
	 * some ordering */
	if (b0 > a0 || b->type > a->type) return true;
	return false;
}

/* advance if possible; if cannot, return false, leave i=0, j=1, type=XOR */
static bool
op_advance(struct op_chain *seq, uint8_t which_instr)
{
	struct op	*op = seq->ops + which_instr;
	bool		push_type = false;

	/* advance indices */
	if (OP_ARGS[op->type] == 1) {
		/* advance i */
		if (++op->i == which_instr + 4) {
			/* i cannot advance; reset the only used index */
			op->i = 0;
			push_type = true;
		}
	} else {
		/* advance j */
		if (++op->j == which_instr + 4) {
			/* j cannot advance; advance i, set j=i+1 */
			op->j = ++op->i + 1;
			if (op->j == which_instr + 4) {
				/* i cannot advance; reset the used indices */
				op->i = 0;
				op->j = 1;
				push_type = true;
			}
		}
	}

	/* this op was changed */
	seq->dirty[which_instr + 4] = true;

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
		bool advanced;
		while ((advanced = op_advance(seq, i - 1))) {
			/* if this is the first operation after seq->hold,
			 * or if operation N-1 < operation N, good; these
			 * checks ensure that operations cannot just be
			 * switched around to yield more pointless
			 * possibilities */
			if (seq->hold + 1 == i ||
			    op_ordered(seq->ops + i - 2, seq->ops + i - 1))
				break;
		}
		if (advanced) break;

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

		const struct op *op = seq->ops + i;

		/* for each input value */
		for (uint8_t j = 0; j < 16; j++) {
			uint8_t	*vals = seq->vals[j];
			uint8_t	r;

			switch (op->type) {
			case OP_XOR:
				r = vals[op->i] ^ vals[op->j];
				break;
			case OP_AND:
				r = vals[op->i] & vals[op->j];
				break;
			case OP_OR:
				r = vals[op->i] | vals[op->j];
				break;
			case OP_NOT:
				r = ~vals[op->i];
				break;
			default:
				assert(0);
			}
			vals[i+4] = r;
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

struct brute_thread_args {
	struct thread_list	*thread_list;

	pthread_mutex_t		*best_lock;
	unsigned		*best;
	struct op_chain		*best_seq;
	unsigned		*best_generation;

	struct op_chain		seq;
	unsigned		found;
	unsigned		last_len;
	unsigned		sboxnum;
	bool			inverse;
};
void *
brute_thread(void *voidarg)
{
	struct brute_thread_args *args = (struct brute_thread_args *)voidarg;

	pthread_mutex_t		*best_lock = args->best_lock;
	unsigned		*best = args->best;
	struct op_chain		*best_seq = args->best_seq;
	unsigned		*best_generation = args->best_generation;

	struct op_chain		seq = args->seq;
	unsigned		found = args->found;
	unsigned		last_len = args->last_len;
	unsigned		sboxnum = args->sboxnum;
	bool			inverse = args->inverse;

	unsigned		threadnum =
	    thread_list_num_of(args->thread_list, pthread_self());
	unsigned		old_generation;

	/* each thread computes to make it easier to do lookups */
	unsigned		y[16][4];

	/* precompute results of sbox cumputations using slow method */
	for (uint8_t i = 0; i < 16; i++) {
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

	old_generation = 0;
	for (;;) {
		if (seq.sz != last_len) {
			last_len = seq.sz;
			/* force a generation check */
			old_generation = 0;
			printf("%u: sz %hhu\n", threadnum, last_len);
		}

		/* the value of 'found' is the y value you're looking for
		 * (e.g. found==1, you have y0 and are looking for y1);
		 * if another thread found something better than this thread
		 * can, stop */
		unsigned cur_generation = *best_generation;
		if (old_generation != cur_generation) {
			for (unsigned i = 0; i < found; i++)
				if (best[i] < seq.hold_vals[i]) {
					printf("%u: old value beaten\n",
					    threadnum);
					return 0;
				}
			if (best[found] < last_len) {
				printf("%u: cannot attain best\n", threadnum);
				return 0;
			} else if (found == 3 && best[3] == last_len) {
				printf("%u: cannot beat best\n", threadnum);
				return 0;
			}
			old_generation = cur_generation;
		}

		/* for this guess, compute the values of each temporary
		 * that has changed */
		run_chain(&seq);

		/* for each column in y[], find a column in vals[] that
		 * matches */
		for (unsigned i = 0; i < 4; i++) {
			unsigned	j;
			bool		match;

			/* already found */
			if (seq.indices[i] < MAX_VALS) continue;

			/* check only the last column of vals[]; all
			 * possible permutations of the previous columns
			 * have already been seen and yielded no fruits */
			j = seq.sz + 3;

			/* check each number in the column with y */
			match = true;
			for (unsigned k = 0; k < 16; k++)
				if (y[k][i] != seq.vals[k][j]) {
					match = false;
					break;
				}
			if (match) {
				/* create child args */
				struct brute_thread_args	child_args;

				if (found < 3)
					child_args.seq = seq;
				seq.indices[i] = j;
				seq.hold = seq.sz;
				seq.hold_vals[found] = seq.sz;
				printf("%u: partial match for %hhu\n",
				    threadnum, i);
				print_chain(stdout, &seq);

				/* update best array */
				pthread_mutex_lock(best_lock);
				/* first check if a better solution existed
				 * because of a race */
				for (unsigned i = 0; i < found; i++)
					if (best[i] < seq.hold_vals[i]) {
						printf("%u: old value beaten "
						    "(race)\n", threadnum);
						pthread_mutex_unlock(
						    best_lock);
						return 0;
					}
				if (best[found] < last_len) {
					printf("%u: not best (race)\n",
					    threadnum);
					pthread_mutex_unlock(best_lock);
					return 0;
				} else if (best[found] > last_len)
					*best_seq = seq;
				best[found] = last_len;
				/* this is sloppy and so may not work on
				 * certain architectures like PowerPC */
				++*best_generation;
				pthread_mutex_unlock(best_lock);

				found++;

				if (found == 4) {
					FILE *tmp = fopen("tmp.hpp", "w");
					print_function(tmp, (uint8_t)sboxnum,
					    inverse, &seq);
					fclose(tmp);
					return 0;
				} else {
					/* create child thread */
					child_args.thread_list =
					    args->thread_list;
					child_args.best_lock = best_lock;
					child_args.best = best;
					child_args.best_seq = best_seq;
					child_args.best_generation =
					    best_generation;
					child_args.found = found - 1;
					child_args.last_len = last_len;
					child_args.sboxnum = sboxnum;
					child_args.inverse = inverse;

					for (int k = 0; k < MAX_VALS; k++)
						child_args.seq.dirty[k] = true;
					op_chain_advance(&child_args.seq);

					thread_list_add(args->thread_list,
					    brute_thread,
					    &child_args, sizeof(child_args));
				}
			}
		}

		op_chain_advance(&seq);
	}

	return 0;
}

void
brute_sbox(uint8_t sboxnum, bool inverse, struct op_chain *out_seq)
{
	/*
	struct thread_list	*thread_list;

	pthread_mutex_t		*best_lock;
	unsigned		*best;
	struct op_chain		*best_seq;

	struct op_chain		seq;
	unsigned		found;
	unsigned		last_len;
	unsigned		sboxnum;
	bool			inverse;
	*/
	struct brute_thread_args	args;
	struct thread_list		thread_list;
	pthread_mutex_t			best_lock;

	unsigned	best[4] = { MAX_OPS, MAX_OPS, MAX_OPS, MAX_OPS };
	unsigned	best_generation = 1;

	args.thread_list = &thread_list;
	args.best_lock = &best_lock;
	args.best = best;
	args.best_seq = out_seq;
	args.best_generation = &best_generation;
	op_chain_init(&args.seq);
	args.found = 0;
	args.last_len = 1;
	args.sboxnum = sboxnum;
	args.inverse = inverse;

	thread_list_init(&thread_list);
	pthread_mutex_init(&best_lock, 0);

	thread_list_add(&thread_list, brute_thread, &args, sizeof(args));
	thread_list_join_destroy(&thread_list);
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
