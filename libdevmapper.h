#ifndef LIB_DEVICE_MAPPER_H
#define LIB_DEVICE_MAPPER_H

/* The only functions I need from <libdevmapper.h>. It cannot be directly
 * included by C++ source. Thanks, guys. */

#include <features.h>
#ifdef __cplusplus
#	include <tr1/cstdint>
#else
#	include <stdint.h>
#endif

/* let's hope they don't change these on us */
enum {
	DM_DEVICE_CREATE,
	DM_DEVICE_RELOAD,
	DM_DEVICE_REMOVE,
	DM_DEVICE_REMOVE_ALL,

	DM_DEVICE_SUSPEND,
	DM_DEVICE_RESUME,

	DM_DEVICE_INFO,
	DM_DEVICE_DEPS,
	DM_DEVICE_RENAME,

	DM_DEVICE_VERSION,

	DM_DEVICE_STATUS,
	DM_DEVICE_TABLE,
	DM_DEVICE_WAITEVENT,

	DM_DEVICE_LIST,

	DM_DEVICE_CLEAR,

	DM_DEVICE_MKNODES,

	DM_DEVICE_LIST_VERSIONS,

	DM_DEVICE_TARGET_MSG,

	DM_DEVICE_SET_GEOMETRY
};


typedef void (*dm_log_fn) (int level, const char *file, int line,
			   const char *f, ...)
    __attribute__ ((format(printf, 4, 5)));

__BEGIN_DECLS

void dm_log_init(dm_log_fn fn);
void dm_log_init_verbose(int level);

struct dm_task;

struct	dm_task *dm_task_create(int type);
void	dm_task_destroy(struct dm_task *dmt);
int	dm_task_set_name(struct dm_task *dmt, const char *name);
int	dm_task_add_target(struct dm_task *dmt, uint64_t start, uint64_t size,
	    const char *ttype, const char *params);
int	dm_task_run(struct dm_task *dmt);
int	dm_task_set_uuid(struct dm_task *dmt, const char *uuid);

__END_DECLS

#endif
