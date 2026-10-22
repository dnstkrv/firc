#ifndef FIRC_INBOUND_CHECK_H
#define FIRC_INBOUND_CHECK_H

#include <stdbool.h>

#include "firc/err.h"
#include "firc/models.h"
#include "firc/tunnels.h"
#include "firc/tunrun.h"

/* WAN role of each app.link entry at start, asked of RCI; false when RCI cannot answer (every entry then reads as not
   WAN). Only the daemon's start-time snapshot calls it. */
bool firc_inbounds_wan_table(const firc_app_config_t *app, bool *wan);

/* Save-time refusals for the inbounds of want: listen a LAN entry of the running app.link as the supervisor judges it,
   port not the WebUI's, the DNS proxy's or 53, and a bind probe unless an enabled running tunnel holds the same listen
   and port; FIRC_ERR_INVAL with err set. Makes no RCI call. */
firc_err_t firc_inbounds_check(const firc_tunnels_t *want, const firc_tunrun_t *run, const firc_app_config_t *app,
                               firc_tun_err_t *err);

#endif
