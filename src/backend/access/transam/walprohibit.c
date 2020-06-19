/*-------------------------------------------------------------------------
 *
 * walprohibit.c
 * 		PostgreSQL write-ahead log prohibit states
 *
 *
 * Portions Copyright (c) 2020, PostgreSQL Global Development Group
 *
 * src/backend/access/transam/walprohibit.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/walprohibit.h"
#include "postmaster/bgwriter.h"
#include "storage/procsignal.h"

/*
 * ProcessBarrierWALProhibit()
 *
 * Handle WAL prohibit state change request.
 */
bool
ProcessBarrierWALProhibit(void)
{
	/*
	 * Kill off any transactions that have an XID *before* allowing the system
	 * to go WAL prohibit state.
	 */
	if (FullTransactionIdIsValid(GetTopFullTransactionIdIfAny()))
	{
		/*
		 * XXX: Kill off the whole session by throwing FATAL instead of killing
		 * transaction by throwing ERROR due to following reasons that need be
		 * thought:
		 *
		 * 1. Due to some presents challenges with the wire protocol, we could
		 * not simply kill of idle transaction.
		 *
		 * 2. If we are here in subtransaction then the ERROR will kill the
		 * current subtransaction only. In the case of invalidations, that
		 * might be good enough, but for XID assignment it's not, because
		 * assigning an XID to a subtransaction also causes higher
		 * sub-transaction levels and the parent transaction to get XIDs.
		 */
		ereport(FATAL,
				(errcode(ERRCODE_ACTIVE_SQL_TRANSACTION),
				 errmsg("system is now read only"),
				 errhint("Cannot continue a transaction if it has performed writes while system is read only.")));
	}

	/* Return to "check" state */
	ResetLocalXLogInsertAllowed();

	return true;
}

/*
 * AlterSystemSetWALProhibitState
 *
 * Execute ALTER SYSTEM READ { ONLY | WRITE } statement.
 */
void
AlterSystemSetWALProhibitState(AlterSystemWALProhibitState *stmt)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to execute ALTER SYSTEM command")));

	/* Alter WAL prohibit state not allowed during recovery */
	PreventCommandDuringRecovery("ALTER SYSTEM");

	/* Yet to add ALTER SYTEM READ WRITE support */
	if (!stmt->WALProhibited)
		elog(ERROR, "XXX: Yet to implement");

	MakeReadOnlyXLOG();
	WaitForProcSignalBarrier(EmitProcSignalBarrier(PROCSIGNAL_BARRIER_WALPROHIBIT));
}
