/*
 * walprohibit.h
 *
 * PostgreSQL write-ahead log prohibit states
 *
 * Portions Copyright (c) 2020, PostgreSQL Global Development Group
 *
 * src/include/access/walprohibit.h
 */
#ifndef WALPROHIBIT_H
#define WALPROHIBIT_H

#include "access/xact.h"
#include "access/xlog.h"
#include "miscadmin.h"
#include "nodes/parsenodes.h"

extern bool ProcessBarrierWALProhibit(void);
extern void AlterSystemSetWALProhibitState(AlterSystemWALProhibitState *stmt);

#endif		/* WALPROHIBIT_H */
