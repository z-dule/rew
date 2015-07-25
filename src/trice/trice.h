/**
 * @file ice.h  Internal Interface to ICE
 *
 * Copyright (C) 2010 Creytiv.com
 */


#ifndef RELEASE
#define ICE_TRACE 1    /**< Trace connectivity checks */
#endif


struct ice_tcpconn;
struct ice_conncheck;


/**
 * Active Checklist. Only used by Full-ICE/Tricle-ICE
 */
struct ice_checklist {
	struct trice *icem;     /* parent */

	enum ice_checkl_state state; /**< State of the checklist             */
	struct tmr tmr_pace;         /**< Timer for pacing STUN requests     */
	uint32_t interval;
	struct stun *stun;           /**< STUN Transport                     */
	struct list conncheckl;
	bool use_cand;

	/* callback handlers */
	ice_estab_h *estabh;
	ice_failed_h *failh;
	void *arg;
};


/**
 * Defines an ICE media-stream
 *
 * NOTE: We try to follow the Resource Acquisition Is Initialization (RAII)
 *       programming idiom, which means:
 *
 * - at any time is the number of local/remote candidates correct
 * - at any time is the checklist up to date (matching local/remote candidates)
 *
 */
struct trice {
	struct trice_conf conf;
	bool controlling;            /**< Local role                         */
	uint64_t tiebrk;             /**< Tie-break value for roleconflict   */

	/* stun/authentication */
	char *lufrag;                /**< Local Username fragment            */
	char *lpwd;                  /**< Local Password                     */
	char *rufrag;                /**< Remote Username fragment           */
	char *rpwd;                  /**< Remote Password                    */

	struct list lcandl;          /**< local candidates (add order)       */
	struct list rcandl;          /**< remote candidates (add order)      */
	struct list checkl;          /**< Check List of cand pairs (sorted)  */
	struct list validl;          /**< Valid List of cand pairs (sorted)  */

	struct ice_checklist *checklist;

	struct list connl;           /**< TCP-connections for all components */
};


/* return TRUE if handled */
typedef bool (tcpconn_frame_h)(struct trice *icem,
			       struct tcp_conn *tc, struct sa *src,
			       struct mbuf *mb, void *arg);

/**
 * Defines a TCP-connection from local-adress to remote-address
 *
 * - one TCP-connection can be shared by multiple candidate pairs
 *
 * - one TCP-connection is always created by the Local Candidate
 */
struct ice_tcpconn {
	struct trice *icem;      /* parent */
	struct le le;
	struct tcp_conn *tc;
	struct shim *shim;
	struct sa laddr;
	struct sa paddr;
	unsigned compid;
	int layer;
	bool active;
	bool estab;

	tcpconn_frame_h *frameh;
	void *arg;
};

struct ice_conncheck {
	struct le le;
	struct ice_candpair *pair;    /* pointer */
	struct stun_ctrans *ct_conn;
	struct trice *icem;           /* owner */
	bool use_cand;
	bool term;
};


/* cand */
int trice_add_candidate(struct ice_lcand **candp,
			struct trice *icem, struct list *lst,
			unsigned compid, char *foundation, int proto,
			uint32_t prio, const struct sa *addr,
			enum ice_cand_type type, enum ice_tcptype tcptype);
int trice_cands_debug(struct re_printf *pf, const struct list *lst);


/* candpair */
int  trice_candpair_alloc(struct ice_candpair **cpp, struct trice *icem,
			 struct ice_lcand *lcand, struct ice_rcand *rcand);
void trice_candpair_prio_order(struct list *lst, bool controlling);
void trice_candpair_make_valid(struct trice *icem, struct ice_candpair *pair);
void trice_candpair_failed(struct ice_candpair *cp, int err, uint16_t scode);
void trice_candpair_set_state(struct ice_candpair *cp,
			     enum ice_candpair_state state);
bool trice_candpair_iscompleted(const struct ice_candpair *cp);
bool trice_candpair_cmp_fnd(const struct ice_candpair *cp1,
			   const struct ice_candpair *cp2);
struct ice_candpair *trice_candpair_find(const struct list *lst,
					const struct ice_lcand *lcand,
					const struct ice_rcand *rcand);
int  ice_candpair_with_local(struct trice *icem, struct ice_lcand *lcand);
int  ice_candpair_with_remote(struct trice *icem, struct ice_rcand *rcand);
const char    *ice_candpair_state2name(enum ice_candpair_state st);


/* STUN server */
int trice_stund_recv(struct trice *icem, struct ice_lcand *lcand,
		    void *sock, const struct sa *src,
		    struct stun_msg *req, size_t presz);


/* ICE media */
void ice_switch_local_role(struct trice *ice);
void trice_printf(struct trice *icem, const char *fmt, ...);
void trice_tracef(struct trice *icem, const char *fmt, ...);


/* ICE checklist */
int ice_checklist_debug(struct re_printf *pf, const struct ice_checklist *ic);
void trice_conncheck_schedule_check(struct trice *icem);
int trice_checklist_update(struct trice *icem);


/* ICE conncheck */
int ice_conncheck_stun_request(struct ice_checklist *ic,
			       struct ice_conncheck *cc,
			       struct ice_candpair *cp, void *sock,
			       bool cc_use_cand);
int trice_conncheck_trigged(struct trice *icem, struct ice_candpair *pair,
			   void *sock, bool use_cand);
int ice_conncheck_debug(struct re_printf *pf, const struct ice_conncheck *cc);


/* TCP connections */


int ice_conn_alloc(struct list *connl, struct trice *icem, unsigned compid,
		   bool active, const struct sa *laddr, const struct sa *peer,
		   struct tcp_sock *ts, int layer,
		   tcpconn_frame_h *frameh, void *arg);
struct ice_tcpconn *ice_conn_find(struct list *connl, unsigned compid,
				  const struct sa *laddr,
				  const struct sa *peer);
int ice_conn_debug(struct re_printf *pf, const struct ice_tcpconn *conn);


bool trice_stun_process(struct trice *icem, struct ice_lcand *lcand,
		       int proto, void *sock, const struct sa *src,
		       struct mbuf *mb);