/*-------------------------------------------------------------------------
 *
 * fetch.h
 *	  Abstraction for fetching from source server.
 *
 * The source server can be either a libpq connection to a live system, or
 * a local data directory. The 'rewind_source' struct abstracts the
 * operations to fetch data from the source system, so that the rest of
 * the code doesn't need to care what kind of a source its dealing with.
 *
 * Copyright (c) 2013-2020, PostgreSQL Global Development Group
 *
 *-------------------------------------------------------------------------
 */
#ifndef FETCH_H
#define FETCH_H

#include "access/xlogdefs.h"
#include "file_ops.h"
#include "filemap.h"
#include "libpq-fe.h"

typedef struct rewind_source
{
	/*
	 * Traverse all files in the source data directory, and call 'callback'
	 * on each file.
	 */
	void (*traverse_files) (struct rewind_source *,
							process_file_callback_t callback);

	/*
	 * Fetch a single file into a malloc'd buffer. The file size is returned
	 * in *filesize. The returned buffer is always zero-terminated, which is
	 * handy for text files.
	 */
	char *(*fetch_file) (struct rewind_source *, const char *path,
						 size_t *filesize);

	/*
	 * Request to fetch (part of) a file in the source system, and write it
	 * the corresponding file in the target system. The source implementation
	 * may queue up the request and execute it later when convenient. Call
	 * finish_fetch() to flush the queue and execute all requests.
	 */
	void (*queue_fetch_range) (struct rewind_source *, const char *path,
							   uint64 offset, size_t len);

	/*
	 * Execute all requests queued up with queue_fetch_range().
	 */
	void (*finish_fetch) (struct rewind_source *);

	/*
	 * Get the current WAL insert position in the source system.
	 */
	XLogRecPtr (*get_current_wal_insert_lsn) (struct rewind_source *);

	/*
	 * Free this rewind_source object.
	 */
	void (*destroy) (struct rewind_source *);

} rewind_source;


/*
 * Execute all the actions in 'filemap'.
 */
extern void execute_file_actions(filemap_t *filemap, rewind_source *source);

/* in libpq_fetch.c */
extern rewind_source *init_libpq_source(PGconn *conn);

/* in copy_fetch.c */
extern rewind_source *init_local_source(const char *datadir);

#endif							/* FETCH_H */
