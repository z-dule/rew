/**
 * @file chklist.c  ICE Checklist
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_stun.h>
#include <re_ice.h>
#include <re_trice.h>
#include "trice.h"


#define DEBUG_MODULE "checklist"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void destructor(void *arg)
{
	struct ice_checklist *ic = arg;

	ic->state = ICE_CHECKLIST_IDLE;

	tmr_cancel(&ic->tmr_pace);
	list_flush(&ic->conncheckl);  /* flush before stun deref */
	mem_deref(ic->stun);
}


static void pace_timeout(void *arg)
{
	struct ice_checklist *ic = arg;
	struct trice *icem = (struct trice *)ic->icem;

	if (ic->state == ICE_CHECKLIST_RUNNING) {
		tmr_start(&ic->tmr_pace, ic->interval,
			  pace_timeout, ic);

		trice_conncheck_schedule_check(icem);
	}

	if (ic->state == ICE_CHECKLIST_FAILED)
		return;

	trice_checklist_update(icem);
}


int trice_checklist_start(struct trice *icem, const struct stun_conf *conf,
			 uint32_t interval, bool use_cand,
			 ice_estab_h *estabh, ice_failed_h *failh, void *arg)
{
	struct ice_checklist *ic;
	int err = 0;

	if (!icem)
		return EINVAL;

	if (icem->checklist)
		return 0;

	ic = mem_zalloc(sizeof(*ic), destructor);
	if (!ic)
		return ENOMEM;

	err = stun_alloc(&ic->stun, NULL, NULL, NULL);
	if (err)
		goto out;

	if (conf)
		*stun_conf(ic->stun) = *conf;
	else {
		stun_conf(ic->stun)->rto = 100;
		stun_conf(ic->stun)->rc  =   4;
	}

	ic->state = ICE_CHECKLIST_RUNNING;
	tmr_init(&ic->tmr_pace);

	ic->interval = interval;
	ic->icem = icem;
	ic->use_cand = use_cand;

	tmr_start(&ic->tmr_pace, 1, pace_timeout, ic);

	icem->checklist = ic;

	ic->estabh = estabh;
	ic->failh  = failh;
	ic->arg    = arg;

 out:
	if (err)
		mem_deref(ic);

	return err;
}


enum ice_checkl_state trice_checklist_state(const struct trice *icem)
{
	if (!icem || !icem->checklist)
		return ICE_CHECKLIST_IDLE;

	return icem->checklist->state;
}


/* If all of the pairs in the check list are now either in the Failed or
   Succeeded state:
 */
bool ice_checklist_iscompleted(const struct trice *icem)
{
	struct le *le;

	if (!icem)
		return false;

	for (le = icem->checkl.head; le; le = le->next) {

		const struct ice_candpair *cp = le->data;

		if (!trice_candpair_iscompleted(cp))
			return false;
	}

	return true;
}


/**
 * Scheduling Checks
 */
void trice_conncheck_schedule_check(struct trice *icem)
{
	struct ice_candpair *pair;
	int err = 0;

	/* Find the highest priority pair in that check list that is in the
	   Waiting state. */
	pair = trice_candpair_find_state(&icem->checkl, ICE_CANDPAIR_WAITING);
	if (pair) {
		err = trice_conncheck_send(icem, pair,
					  icem->checklist->use_cand);
		if (err)
			trice_candpair_failed(pair, err, 0);
		return;
	}

	/* If there is no such pair: */

	/* Find the highest priority pair in that check list that is in
	   the Frozen state. */
	pair = trice_candpair_find_state(&icem->checkl, ICE_CANDPAIR_FROZEN);
	if (pair) { /* If there is such a pair: */

		/* Unfreeze the pair.
		   Perform a check for that pair, causing its state to
		   transition to In-Progress. */
		err = trice_conncheck_send(icem, pair,
					  icem->checklist->use_cand);
		if (err)
			trice_candpair_failed(pair, err, 0);
		return;
	}

	/* If there is no such pair: */

	/* Terminate the timer for that check list. */
}


/**
 * Computing States
 */
void trice_checklist_set_waiting(struct trice *icem)
{
	struct le *le, *le2;

	if (!icem)
		return;

	/*
	For all pairs with the same foundation, it sets the state of
	the pair with the lowest component ID to Waiting.  If there is
	more than one such pair, the one with the highest priority is
	used.
	*/

	for (le = icem->checkl.head; le; le = le->next) {

		struct ice_candpair *cp = le->data;

		for (le2 = icem->checkl.head; le2; le2 = le2->next) {

			struct ice_candpair *cp2 = le2->data;

			if (!trice_candpair_cmp_fnd(cp, cp2))
				continue;

			if (cp2->lcand->attr.compid < cp->lcand->attr.compid &&
			    cp2->pprio > cp->pprio)
				cp = cp2;
		}

		if (cp->state == ICE_CANDPAIR_FROZEN)
			trice_candpair_set_state(cp, ICE_CANDPAIR_WAITING);
	}
}


int trice_checklist_update(struct trice *icem)
{
	struct ice_checklist *ic;

	if (!icem)
		return EINVAL;

	ic = icem->checklist;
	if (!ic)
		return ENOSYS;

	if (ice_checklist_iscompleted(icem)) {

		if (list_isempty(&icem->validl)) {
			ic->state = ICE_CHECKLIST_FAILED;
		}
		else {
			ic->state = ICE_CHECKLIST_COMPLETED;
		}

		tmr_cancel(&ic->tmr_pace);
	}

	return 0;
}


int ice_checklist_debug(struct re_printf *pf, const struct ice_checklist *ic)
{
	struct le *le;
	int err = 0;

	if (!ic)
		return 0;

	err |= re_hprintf(pf, " Checklist: state=%s, interval=%u\n",
			  ice_checkl_state2name(ic->state), ic->interval);
	err |= re_hprintf(pf, " Pending connchecks: %u\n",
			  list_count(&ic->conncheckl));
	for (le = ic->conncheckl.head; le; le = le->next) {
		struct ice_conncheck *cc = le->data;

		err |= re_hprintf(pf, " ...%H\n", ice_conncheck_debug, cc);
	}

	err |= stun_debug(pf, ic->stun);

	return err;
}


const char *ice_checkl_state2name(enum ice_checkl_state cst)
{
	switch (cst) {

	case ICE_CHECKLIST_IDLE:      return "Idle";
	case ICE_CHECKLIST_RUNNING:   return "Running";
	case ICE_CHECKLIST_COMPLETED: return "Completed";
	case ICE_CHECKLIST_FAILED:    return "Failed";
	default:                  return "???";
	}
}


struct stun *trice_stun(struct trice *icem)
{
	if (!icem || !icem->checklist)
		return NULL;

	return icem->checklist->stun;
}