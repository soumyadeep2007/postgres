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

/* WAL Prohibit States */
#define	WALPROHIBIT_STATE_READ_WRITE		0x0000
#define	WALPROHIBIT_STATE_READ_ONLY			0x0001

/*
 * The bit is used in state transition from one state to another.  When this
 * bit is set then the state indicated by the 0th position bit is yet to
 * confirmed.
 */
#define WALPROHIBIT_TRANSITION_IN_PROGRESS	0x0002

#endif		/* WALPROHIBIT_H */
