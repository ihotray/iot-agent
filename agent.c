#include <iot/mongoose.h>
#include <iot/iot.h>
#include "mqtt.h"
#include "agent.h"

static int s_signo;
static void signal_handler(int signo) {
    s_signo = signo;
}

void timer_session_fn(void *arg);

int agent_init(void **priv, void *opts) {

    struct agent_private *p;
    int timer_opts = MG_TIMER_REPEAT | MG_TIMER_RUN_NOW;

    signal(SIGINT, signal_handler);   // Setup signal handlers - exist event
    signal(SIGTERM, signal_handler);  // manager loop on SIGINT and SIGTERM

    *priv = NULL;
    p = calloc(1, sizeof(struct agent_private));
    if (!p)
        return -1;
    
    //生成agent id
    char rnd[10];
    mg_random(rnd, sizeof(rnd));
    mg_hex(rnd, sizeof(rnd), p->agent_id);
    
    p->cfg.opts = opts;
    mg_log_set(p->cfg.opts->debug_level);

    p->fs = &mg_fs_posix;

    mg_mgr_init(&p->mgr);
    p->mgr.dnstimeout = p->cfg.opts->dns4_timeout*1000;
    p->mgr.dns4.url = p->cfg.opts->dns4_url;

    p->mgr.userdata = p;

    mg_timer_add(&p->mgr, 1000, timer_opts, timer_mqtt_fn, &p->mgr);
    mg_timer_add(&p->mgr, 1000, timer_opts, timer_cloud_mqtt_fn, &p->mgr);

    mg_timer_add(&p->mgr, 1000, timer_opts, timer_session_fn, &p->mgr);

    *priv = p;

    return 0;

}


void agent_run(void *handle) {
    struct agent_private *priv = (struct agent_private *)handle;
    while (s_signo == 0) mg_mgr_poll(&priv->mgr, 1000);  // Event loop, 1000ms timeout
}

void agent_exit(void *handle) {
    struct agent_private *priv = (struct agent_private *)handle;
    mg_mgr_free(&priv->mgr);
    free(handle);
}

int agent_main(void *user_options) {

    struct agent_option *opts = (struct agent_option *)user_options;
	void *agent_handle;
	int ret;

    ret = agent_init(&agent_handle, opts);
    if (ret)
        exit(EXIT_FAILURE);

    agent_run(agent_handle);

    agent_exit(agent_handle);

    return 0;

}