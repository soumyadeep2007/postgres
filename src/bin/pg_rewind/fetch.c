/*-------------------------------------------------------------------------
 *
 * fetch.c
 *	  Functions for fetching files from a local or remote data dir
 *
 * This file forms an abstraction of getting files from the "source".
 * There are two implementations of this interface: one for copying files
 * from a data directory via normal filesystem operations (copy_fetch.c),
 * and another for fetching files from a remote server via a libpq
 * connection (libpq_fetch.c)
 *
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 *
 *-------------------------------------------------------------------------
 */
#include "postgres_fe.h"

#include <sys/stat.h>
#include <unistd.h>

#include "fetch.h"
#include "file_ops.h"
#include "filemap.h"
#include "pg_rewind.h"

/*
 * Execute the actions in the file map, fetching data from the source
 * system as needed.
 */
void
execute_file_actions(filemap_t *filemap, rewind_source *source)
{
	int			i;

	for (i = 0; i < filemap->nactions; i++)
	{
		file_entry_t *entry = filemap->actions[i];
		datapagemap_iterator_t *iter;
		BlockNumber blkno;
		off_t		offset;

		/*
		 * If this is a relation file, copy the modified blocks.
		 *
		 * This is in addition to any other changes.
		 */
		iter = datapagemap_iterate(&entry->target_modified_pages);
		while (datapagemap_next(iter, &blkno))
		{
			offset = blkno * BLCKSZ;

			source->queue_fetch_range(source, entry->path, offset, BLCKSZ);
		}
		pg_free(iter);

		switch (entry->action)
		{
			case FILE_ACTION_NONE:
				/* nothing else to do */
				break;

			case FILE_ACTION_COPY:
				/* Truncate the old file out of the way, if any */
				open_target_file(entry->path, true);
				source->queue_fetch_range(source, entry->path,
										  0, entry->source_size);
				break;

			case FILE_ACTION_TRUNCATE:
				truncate_target_file(entry->path, entry->source_size);
				break;

			case FILE_ACTION_COPY_TAIL:
				source->queue_fetch_range(source, entry->path,
										  entry->target_size,
										  entry->source_size - entry->target_size);
				break;

			case FILE_ACTION_REMOVE:
				remove_target(entry);
				break;

			case FILE_ACTION_CREATE:
				create_target(entry);
				break;

			case FILE_ACTION_UNDECIDED:
				pg_fatal("no action decided for \"%s\"", entry->path);
				break;
		}
	}

	/*
	 * We've now copied the list of file ranges that we need to fetch to the
	 * temporary table. Now, actually fetch all of those ranges. XXX
	 */
	source->finish_fetch(source);

	close_target_file();
}
