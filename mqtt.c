
#include <lualib.h>
#include <lauxlib.h>
#include <iot/cJSON.h>
#include <iot/mongoose.h>
#include <iot/iot.h>
#include "agent.h"

/*
device/%s/rpc/request/+
device/%s/rpc/response/%s
*/

/*
|------------------device-----------------|----------------------cloud-------------|
iot-rpcd <---> iot-mqtt <---> iot-agent <---> iot-mqtt-cloud <--->  cloud-controller


1. cloud-cotroller --req msg--> iot-agent --resp msg--> cloud-cotroller
2. cdoud-cotroller --req msg--> iot-agent --req msg--> iot-rpcd --resp msg--> iot-agent --resp msg--> cloud-cotroller
*/

/*
|------------------agent device-----------|------controller device---------|
iot-rpcd <---> iot-mqtt <---> iot-agent <---> iot-mqtt <--->  iot-controller

1. iot-cotroller --req msg--> iot-agent --req msg--> iot-rpcd --resp msg--> iot-agent --resp msg--> iot-cotroller
*/


void rpc_local_msg_handler(struct mg_connection *c, struct mg_str topic, struct mg_str data);
void rpc_agent_msg_handler(struct mg_connection *c, struct mg_str topic, struct mg_str data);


static void mqtt_ev_open_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    MG_INFO(("mqtt client connection created"));
}

static void mqtt_ev_connect(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    MG_INFO(("mqtt client connection connected"));
}

static void mqtt_ev_error_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    MG_ERROR(("%p %s", c->fd, (char *) ev_data));
    c->is_closing = 1;
}

static void mqtt_ev_poll_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;
    if (!priv->cfg.opts->mqtt_keepalive) //no keepalive
        return;

    uint64_t now = mg_millis();

    if (priv->pong_active && now > priv->pong_active &&
        now - priv->pong_active > (priv->cfg.opts->mqtt_keepalive + 3)*1000) { //TODO
        MG_INFO(("mqtt client connction timeout"));
        c->is_draining = 1;
    }

}

static void mqtt_ev_close_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;
    MG_INFO(("mqtt client connection closed"));
    priv->mqtt_conn = NULL; // Mark that we're closed

}


static void mqtt_ev_mqtt_open_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    // MQTT connect is successful
    char *topic = mg_mprintf(IOT_AGENT_TOPIC, priv->agent_id);
    struct mg_str subt = mg_str(topic);

    MG_INFO(("connect to mqtt server: %s", priv->cfg.opts->mqtt_serve_address));
    struct mg_mqtt_opts sub_opts;
    memset(&sub_opts, 0, sizeof(sub_opts));
    sub_opts.topic = subt;
    sub_opts.qos = MQTT_QOS;
    mg_mqtt_sub(c, &sub_opts);
    MG_INFO(("subscribed to %.*s", (int) subt.len, subt.ptr));
    free(topic);

    topic = mg_mprintf(IOT_AGENT_PROXY_RESP_TOPIC, priv->agent_id);
    subt = mg_str(topic);
    sub_opts.topic = subt;
    mg_mqtt_sub(c, &sub_opts);
    MG_INFO(("subscribed to %.*s", (int) subt.len, subt.ptr));
    free(topic);

}

static void mqtt_ev_mqtt_cmd_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;
    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    if (mm->cmd == MQTT_CMD_PINGRESP) {
        priv->pong_active = mg_millis();
    }
}

static void mqtt_ev_mqtt_msg_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;
    MG_DEBUG(("received %.*s <- %.*s", (int) mm->data.len, mm->data.ptr,
        (int) mm->topic.len, mm->topic.ptr));

    // handle msg
    rpc_local_msg_handler(c, mm->topic, mm->data);

}

static void mqtt_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    switch (ev) {
        case MG_EV_OPEN:
            mqtt_ev_open_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_CONNECT:
            mqtt_ev_connect(c, ev, ev_data, fn_data);
            break;

        case MG_EV_ERROR:
            mqtt_ev_error_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_MQTT_OPEN:
            mqtt_ev_mqtt_open_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_MQTT_CMD:
            mqtt_ev_mqtt_cmd_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_MQTT_MSG:
            mqtt_ev_mqtt_msg_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_POLL:
            mqtt_ev_poll_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_CLOSE:
            mqtt_ev_close_cb(c, ev, ev_data, fn_data);
            break;
    }
}

// Timer function - recreate client connection if it is closed
void timer_mqtt_fn(void *arg) {
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    struct agent_private *priv = (struct agent_private*)mgr->userdata;
    uint64_t now = mg_millis();

    if (priv->mqtt_conn == NULL) {
        struct mg_mqtt_opts opts = {.clean = true,
                                .qos = MQTT_QOS,
                                .message = mg_str("goodbye"),
                                .keepalive = priv->cfg.opts->mqtt_keepalive};
        priv->mqtt_conn = mg_mqtt_connect(mgr, priv->cfg.opts->mqtt_serve_address, &opts, mqtt_cb, NULL);
        priv->ping_active = now;
        priv->pong_active = now;

    } else if (priv->cfg.opts->mqtt_keepalive) { //need keep alive
        
        if (now < priv->ping_active) {
            MG_INFO(("system time loopback"));
            priv->ping_active = now;
            priv->pong_active = now;
        }
        if (now - priv->ping_active >= priv->cfg.opts->mqtt_keepalive * 1000) {
            mg_mqtt_ping(priv->mqtt_conn);
            priv->ping_active = now;
        }
    }
}
// cloud mqtt connect/disconnect callback
void cloud_mqtt_event_callback(struct mg_mgr *mgr, const char* event) {
    struct agent_private *priv = (struct agent_private *)mgr->userdata;
    char *params = NULL;
    cJSON *root = NULL;

    lua_State *L = luaL_newstate();

    luaL_openlibs(L);

    if ( luaL_dofile(L, priv->cfg.opts->callback_lua) ) {
        MG_ERROR(("lua dofile %s failed", priv->cfg.opts->callback_lua));
        goto done;
    }

    lua_getfield(L, -1, "on_event");
    if (!lua_isfunction(L, -1)) {
        MG_ERROR(("method on_event is not a function"));
        goto done;
    }

    root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "event", event);
    cJSON_AddStringToObject(root, "address", priv->cfg.opts->cloud_mqtt_serve_address);

    params = cJSON_Print(root);

    MG_INFO(("callback on_event: %s", params));

    lua_pushstring(L, params);

    if (lua_pcall(L, 1, 0, 0)) {//one params, zero return values, zero error func
        MG_ERROR(("callback failed"));
        goto done;
    }

done:
    if (L)
        lua_close(L);
    if (params)
        free(params);
    if (root)
        cJSON_Delete(root);

}

static void cloud_mqtt_ev_open_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    MG_INFO(("cloud mqtt client connection created"));
}

static void cloud_mqtt_ev_connect(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    MG_INFO(("cloud mqtt client connection connected"));

    if (mg_url_is_ssl(priv->cfg.opts->cloud_mqtt_serve_address)) {

        struct mg_tls_opts opts = {
            .ca = priv->cfg.opts->cloud_mqtts_ca,
            .cert = priv->cfg.opts->cloud_mqtts_cert,
            .certkey = priv->cfg.opts->cloud_mqtts_certkey
        };

        mg_tls_init(c, &opts);

    }

}

static void cloud_mqtt_ev_error_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    MG_ERROR(("%lu %s", c->id, (char *) ev_data));
    c->is_closing = 1;
}

static void cloud_mqtt_ev_poll_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;
    if (!priv->cfg.opts->cloud_mqtt_keepalive) //no keepalive
        return;

    uint64_t now = mg_millis();

    if (priv->cloud_pong_active && now > priv->cloud_pong_active &&
        now - priv->cloud_pong_active > (priv->cfg.opts->cloud_mqtt_keepalive + 3)*1000) { //TODO
        MG_INFO(("cloud mqtt client connction timeout"));
        c->is_draining = 1;
    }

}

static void cloud_mqtt_ev_close_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;
    MG_INFO(("cloud mqtt client connection closed"));
    priv->cloud_mqtt_conn = NULL; // Mark that we're closed

    cloud_mqtt_event_callback(c->mgr, "disconnected");

}

static void cloud_mqtt_ev_mqtt_open_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    // MQTT connect is successful
    char *topic = mg_mprintf(IOT_AGENT_REQ_TOPIC, priv->cfg.opts->cloud_mqtt_username);
    struct mg_str subt = mg_str(topic);

    MG_INFO(("connect to mqtt server: %s", priv->cfg.opts->cloud_mqtt_serve_address));
    struct mg_mqtt_opts sub_opts;
    memset(&sub_opts, 0, sizeof(sub_opts));
    sub_opts.topic = subt;
    sub_opts.qos = MQTT_QOS;
    mg_mqtt_sub(c, &sub_opts);
    MG_INFO(("subscribed to %.*s", (int) subt.len, subt.ptr));
    free(topic);

    cloud_mqtt_event_callback(c->mgr, "connected");

}

static void cloud_mqtt_ev_mqtt_cmd_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;
    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    if (mm->cmd == MQTT_CMD_PINGRESP) {
        priv->cloud_pong_active = mg_millis();
    }

}


static void cloud_mqtt_ev_mqtt_msg_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct mg_mqtt_message *mm = (struct mg_mqtt_message *) ev_data;
    MG_DEBUG(("received %.*s <- %.*s", (int) mm->data.len, mm->data.ptr,
        (int) mm->topic.len, mm->topic.ptr));

    // handle msg
    rpc_agent_msg_handler(c, mm->topic, mm->data);

}


static void cloud_mqtt_cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    switch (ev) {
        case MG_EV_OPEN:
            cloud_mqtt_ev_open_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_CONNECT:
            cloud_mqtt_ev_connect(c, ev, ev_data, fn_data);
            break;

        case MG_EV_ERROR:
            cloud_mqtt_ev_error_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_MQTT_OPEN:
            cloud_mqtt_ev_mqtt_open_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_MQTT_CMD:
            cloud_mqtt_ev_mqtt_cmd_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_MQTT_MSG:
            cloud_mqtt_ev_mqtt_msg_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_POLL:
            cloud_mqtt_ev_poll_cb(c, ev, ev_data, fn_data);
            break;

        case MG_EV_CLOSE:
            cloud_mqtt_ev_close_cb(c, ev, ev_data, fn_data);
            break;
    }
}


// Timer function - recreate client connection if it is closed
void timer_cloud_mqtt_fn(void *arg) {
    struct mg_mgr *mgr = (struct mg_mgr *)arg;
    struct agent_private *priv = (struct agent_private*)mgr->userdata;
    uint64_t now = mg_millis();

    if (priv->cloud_mqtt_conn == NULL) {
        struct mg_mqtt_opts opts = {.clean = true,
                                .qos = MQTT_QOS,
                                .message = mg_str("goodbye"),
                                .keepalive = priv->cfg.opts->cloud_mqtt_keepalive,
                                .version = 4,
                                .user = mg_str(priv->cfg.opts->cloud_mqtt_username),
                                .pass = mg_str(priv->cfg.opts->cloud_mqtt_password)};
        priv->cloud_mqtt_conn = mg_mqtt_connect(mgr, priv->cfg.opts->cloud_mqtt_serve_address, &opts, cloud_mqtt_cb, NULL);
        priv->cloud_ping_active = now;
        priv->cloud_pong_active = now;

    } else if (priv->cfg.opts->cloud_mqtt_keepalive) { //need keep alive
        
        if (now < priv->cloud_ping_active) {
            MG_INFO(("system time loopback"));
            priv->cloud_ping_active = now;
            priv->cloud_pong_active = now;
        }
        if (now - priv->cloud_ping_active >= priv->cfg.opts->cloud_mqtt_keepalive * 1000) {
            mg_mqtt_ping(priv->cloud_mqtt_conn);
            priv->cloud_ping_active = now;
        }
    }
}