#include <iot/cJSON.h>
#include <iot/mongoose.h>
#include <iot/iot.h>
#include "agent.h"

struct iot_http_info {
    mg_md5_ctx md5_ctx;
    char url[MG_PATH_MAX];
    char filename[MG_PATH_MAX];
    char filepath[MG_PATH_MAX];
    char topic[MQTT_MAX_TOPIC_LEN];
    int filesize;
    void *fd;
    bool success;
};


void rpc_local_rpcd_handler(struct mg_connection *c, struct mg_str topic, struct mg_str data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    char *prefix = mg_mprintf(IOT_AGENT_TOPIC_RPEFIX, priv->agent_id);
    struct mg_str topic_prefix = mg_str(prefix);
    struct mg_str controller_topic_type = mg_str(IOT_CONTROLLER_TOPIC_TYPE);

    //delete mg/iot-agent/{agent-id}/
    struct mg_str topic_type = mg_str_n(topic.ptr + topic_prefix.len, topic.len - topic_prefix.len);

    if (topic_type.len > controller_topic_type.len) {
        topic_type = mg_str_n(topic_type.ptr, controller_topic_type.len);
    }

    if (!mg_strcmp(topic_type, controller_topic_type) && priv->cloud_mqtt_conn != NULL) {
        struct mg_str req_info = mg_str_n(topic.ptr + topic_prefix.len + controller_topic_type.len, topic.len - topic_prefix.len - controller_topic_type.len);

        //pub device/{devid}/rpc/response/{ServiceID}/{reqId} via agent-mqtt
        char *pub_topic = mg_mprintf(IOT_AGENT_RESP_TOPIC, priv->cfg.opts->cloud_mqtt_username, req_info.len, req_info.ptr);
        struct mg_str pubt = mg_str(pub_topic);
        struct mg_mqtt_opts pub_opts;
        memset(&pub_opts, 0, sizeof(pub_opts));
        pub_opts.topic = pubt;
        pub_opts.message = data;
        pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
        mg_mqtt_pub(priv->cloud_mqtt_conn, &pub_opts);
        MG_DEBUG(("pub %.*s -> %.*s", (int) data.len, data.ptr,
            (int) pubt.len, pubt.ptr));
        free(pub_topic);
    }

    free(prefix);
}

/*
device/+/rpc/response/{agent_id}/123
*/
static struct mg_str proxy_id(struct mg_str topic, const char *agent_id) {
    struct mg_str sub_topic_prefix = mg_str(agent_id);
    const char *p = mg_strstr(topic, sub_topic_prefix);
    if (p == NULL) {
        return mg_str("0");
    }

    struct mg_str topic_prefix = mg_str_n(p, topic.len - (p - topic.ptr));

    struct mg_str cid = mg_str_n(topic_prefix.ptr + sub_topic_prefix.len + 1, topic_prefix.len - sub_topic_prefix.len -1);
    MG_DEBUG(("topic: %.*s, topic_prefix: %.*s, cid: %.*s", (int)topic.len, topic.ptr, (int)topic_prefix.len, topic_prefix.ptr, (int)cid.len, cid.ptr));
    return cid;
}

void rpc_local_proxy_handler(struct mg_connection *c, struct mg_str topic, struct mg_str data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    struct mg_str pid = proxy_id(topic, priv->agent_id);
    struct agent_session *s, *next;
    for (s = priv->sessions; s != NULL; s = next) {
        next = s->next;
        char id[32] = {0};
        mg_snprintf(id, sizeof(id) - 1, "%lu", s->proxy_id);
        if (mg_strcmp(pid, mg_str(id)) == 0) {
            break;
        }
    }
    if (s == NULL) {
        MG_DEBUG(("proxy id %lu not found", pid));
        return;
    }

    struct mg_str req_info = mg_str(s->req_info);
    char *pub_topic = mg_mprintf(IOT_AGENT_RESP_TOPIC, priv->cfg.opts->cloud_mqtt_username, req_info.len, req_info.ptr);
    struct mg_str pubt = mg_str(pub_topic);

    if (priv->cloud_mqtt_conn != NULL) {
        struct mg_mqtt_opts pub_opts;
        memset(&pub_opts, 0, sizeof(pub_opts));
        pub_opts.topic = pubt;
        pub_opts.message = data;
        pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
        mg_mqtt_pub(priv->cloud_mqtt_conn, &pub_opts);
        MG_DEBUG(("pub %.*s -> %.*s", (int) data.len, data.ptr,
            (int) pubt.len, pubt.ptr));
    }
    LIST_DELETE(struct agent_session, &priv->sessions, s);
    free(s);
    free(pub_topic);

}

/*
[agent-mqtt] from controller
sub device/{devid}/rpc/request/+/+
recevie device/{devid}/rpc/request/{ServiceID}/{reqId}

[local-mqtt] to iot-rpcd
pub mg/iot-agnet/{agent_id}/controller/{ServiceID}/{reqId}/iot-rpcd

[local-mqtt] from iot-rpcd
sub mg/iot-agent/{agent_id}/+/+/+
receive mg/iot-agent/{agent_id}/controller/{ServiceID}/{reqId}

[agent-mqtt] to controller
pub device/{devid}/rpc/response/{ServiceID}/{reqId}
*/

void rpc_local_msg_handler(struct mg_connection *c, struct mg_str topic, struct mg_str data) {

    // receive from rpcd
    // mg/iot-agent/{agent-id}/controller/{ServiceID}/{reqId} or 
    // mg/iot-agent/{agent-id}/local/1/1 or
    // from other agent
    // device/{devid}/rpc/response/{agent_id}/{reqid}
    if (topic.len <= 2) {
        return;
    }

    struct mg_str typ = mg_str_n(topic.ptr, 2);

    if ( !mg_strcmp(typ, mg_str("mg")) ) { //from rpcd
        rpc_local_rpcd_handler(c, topic, data);
    } else { //from proxied agent
        rpc_local_proxy_handler(c, topic, data);
    }
    
}


static void download_fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    struct iot_http_info *hi = (struct iot_http_info *)fn_data;
    if (ev == MG_EV_CONNECT) {
        // Connected to server. Extract host name from URL
        struct mg_str host = mg_url_host(hi->url);

        // If s_url is https://, tell client connection to use TLS
        if (mg_url_is_ssl(hi->url)) {
            struct mg_tls_opts opts = {0};
            mg_tls_init(c, &opts);
        }

        // Send request
        mg_printf(c,
                "GET %s HTTP/1.1\r\n"
                "Connection: keep-alive\r\n"
                "Keep-Alive: timeout=60\r\n"
                "Host: %.*s\r\n"
                "\r\n",
                mg_url_uri(hi->url), (int) host.len, host.ptr);
    } else if (ev == MG_EV_HTTP_CHUNK) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;

        if (hi->fd == NULL && hm->chunk.len) { //open file
            mg_snprintf(hi->filepath, MG_PATH_MAX-1, "%s/iot_cloud_%s", priv->cfg.opts->http_download_dir, hi->filename);
            //删除已有文件
            priv->fs->rm(hi->filepath);
            hi->fd = priv->fs->op(hi->filepath, MG_FS_WRITE);
            mg_md5_init(&hi->md5_ctx);
        }
        if (hi->fd && hm->chunk.len) {
            priv->fs->wr(hi->fd, hm->chunk.ptr, hm->chunk.len);
            mg_md5_update(&hi->md5_ctx, (const unsigned char *)hm->chunk.ptr, hm->chunk.len);
            hi->filesize += hm->chunk.len;
        }

        mg_http_delete_chunk(c, hm);
        if (hm->chunk.len == 0) {// Last chunk
            unsigned char md5[16] = {0};
            char md5sum[33] = {0};
            if (hi->filesize) {
                mg_md5_final(&hi->md5_ctx, md5);
                for (int i=0; i<sizeof(md5); i++) {
                    mg_snprintf(&md5sum[i*2], 3, "%02x", md5[i]);
                }
            }
            if (hi->fd) {
                hi->success = true;
                priv->fs->cl(hi->fd);
                hi->fd = NULL;
                hi->filesize = 0;
                //resonse
                if (priv->cloud_mqtt_conn != NULL) {
                    char *resp = mg_mprintf("{\"code\": 0, \"data\": {\"filename\": \"%s\", \"filepath\": \"%s\", \"md5\": \"%s\"}}",
                                            hi->filename, hi->filepath, md5sum);
                    struct mg_mqtt_opts pub_opts;
                    memset(&pub_opts, 0, sizeof(pub_opts));
                    pub_opts.topic = mg_str(hi->topic);
                    pub_opts.message = mg_str(resp);
                    pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
                    mg_mqtt_pub(priv->cloud_mqtt_conn, &pub_opts);
                    MG_DEBUG(("pub: %s -> %s", resp, hi->topic));
                    free(resp);
                }
            }
        }
    } else if (ev == MG_EV_HTTP_MSG) {
        // Response is received. Print it
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        MG_DEBUG(("download msg"));
        fwrite(hm->body.ptr, 1, hm->body.len, stdout);
        c->is_closing = 1;         // Tell mongoose to close this connection
    } else if (ev == MG_EV_ERROR) {
        c->is_closing = 1;
    } else if (ev == MG_EV_CLOSE) {
        MG_DEBUG(("download finish"));
        if (hi->fd) {
            priv->fs->cl(hi->fd);
        }
        if (hi->success == false && priv->cloud_mqtt_conn != NULL) {
            struct mg_mqtt_opts pub_opts;
            memset(&pub_opts, 0, sizeof(pub_opts));
            pub_opts.topic = mg_str(hi->topic);
            pub_opts.message = mg_str("{\"code\": -1}");
            pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
            mg_mqtt_pub(priv->cloud_mqtt_conn, &pub_opts);
        }
        free(hi);
    }
}

/*
{
    "method": "upload" or "download",
    "param" : {
        "url": "http://xxx.com/zxx",
        "filename": "test.dat"
    }
}
*/
void rpc_agent_download_handler(struct mg_connection *c, struct mg_str pub_topic, cJSON *root) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    cJSON *param, *url, *filename;
    param = cJSON_GetObjectItem(root, FIELD_PARAM);
    url = cJSON_GetObjectItem(param, FIELD_URL);
    filename = cJSON_GetObjectItem(param, FIELD_FILENAME);
    if (!cJSON_IsString(url) || !cJSON_IsString(filename)) {
        MG_ERROR(("URL OR FILENAME IS NOT STRING"));
        //response cloud avoid too many req cache
        if (priv->cloud_mqtt_conn != NULL) {
            struct mg_mqtt_opts pub_opts;
            memset(&pub_opts, 0, sizeof(pub_opts));
            pub_opts.topic = pub_topic;
            pub_opts.message = mg_str("{\"code\": -1}");
            pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
            mg_mqtt_pub(priv->cloud_mqtt_conn, &pub_opts);
        }
        return;
    }

    struct iot_http_info *hi = calloc(1, sizeof(struct iot_http_info));
    if (!hi) {
        MG_ERROR(("OOM"));
        if (priv->cloud_mqtt_conn != NULL) {
            struct mg_mqtt_opts pub_opts;
            memset(&pub_opts, 0, sizeof(pub_opts));
            pub_opts.topic = pub_topic;
            pub_opts.message = mg_str("{\"code\": -1}");
            pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
            mg_mqtt_pub(priv->cloud_mqtt_conn, &pub_opts);
        }
        return;
    }
    mg_snprintf(hi->url, MG_PATH_MAX-1, "%s", cJSON_GetStringValue(url));
    mg_snprintf(hi->filename, MG_PATH_MAX-1, "%s", cJSON_GetStringValue(filename));
    mg_snprintf(hi->topic, MQTT_MAX_TOPIC_LEN-1, "%.*s", pub_topic.len, pub_topic.ptr);
    mg_http_connect(c->mgr, hi->url, download_fn, hi);  // Create client connection

}

void rpc_agent_upload_handler(struct mg_connection *c, struct mg_str pub_topic, cJSON *root) {
}

void rpc_agent_rpcd_handler(struct mg_connection *c, struct mg_str pub_topic, struct mg_str data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    //pub to rpcd via local-mqtt
    if (priv->mqtt_conn != NULL) {
        struct mg_mqtt_opts pub_opts;
        memset(&pub_opts, 0, sizeof(pub_opts));
        pub_opts.topic = pub_topic;
        pub_opts.message = data;
        pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
        mg_mqtt_pub(priv->mqtt_conn, &pub_opts);
        MG_DEBUG(("pub %.*s -> %.*s", (int) data.len, data.ptr, pub_topic.len, pub_topic.ptr));    
    }
}

void rpc_agent_proxy_handler(struct mg_connection *c, struct mg_str req_info, cJSON *root) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    cJSON *to = cJSON_GetObjectItem(root, FIELD_TO);
    const char *to_value = cJSON_GetStringValue(to);

    //save proxy_session
    struct agent_session *s = (struct agent_session *) calloc(1, sizeof(struct agent_session));
    if (NULL == s) {
        MG_ERROR(("OOM"));
        return;
    }
    s->proxy_id = ++priv->proxy_id;
    s->expire = mg_millis() + 300 * 1000; //300s timeout
    mg_snprintf(s->req_info, sizeof(s->req_info) - 1, "%.*s", req_info.len, req_info.ptr);
    LIST_ADD_HEAD(struct agent_session, &priv->sessions, s);

    char *topic = mg_mprintf(IOT_AGENT_PROXY_REQ_TOPIC, to_value, priv->agent_id, s->proxy_id);
    struct mg_str pub_topic = mg_str(topic);
    cJSON_DeleteItemFromObject(root, FIELD_TO);

    char *printed = cJSON_Print(root);
    struct mg_str data = mg_str(printed);
    if (priv->mqtt_conn != NULL) {
        struct mg_mqtt_opts pub_opts;
        memset(&pub_opts, 0, sizeof(pub_opts));
        pub_opts.topic = pub_topic;
        pub_opts.message = data;
        pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
        mg_mqtt_pub(priv->mqtt_conn, &pub_opts);
        MG_DEBUG(("pub %.*s -> %.*s", (int) data.len, data.ptr, pub_topic.len, pub_topic.ptr));    
    }
    free(topic);
    free(printed);
}

//receive device/{devid}/rpc/request/{ServiceID}/{reqId} via agent-mqtt
void rpc_agent_msg_handler(struct mg_connection *c, struct mg_str topic, struct mg_str data) {

    struct agent_private *priv = (struct agent_private*)c->mgr->userdata;

    char *topic_prefix = NULL, *pub_rpcd_topic = NULL, *pub_controller_topic = NULL;

    cJSON *root = cJSON_ParseWithLength(data.ptr, data.len);

    //receive device/{devid}/rpc/request/{ServiceID}/{reqId} via agent-mqtt
    if (mg_strstr(topic, mg_str(IOT_AGENT_DEVICE_ALL_PREFIX))) {
        topic_prefix = mg_mprintf(IOT_AGENT_REQ_TOPIC_PREFIX, IOT_AGENT_DEVICE_ALL);
        cJSON *filter = cJSON_GetObjectItem(root, FIELD_FILTER);
        if (cJSON_IsArray(filter)) {
            bool matched = false;
            cJSON *item = NULL;
            cJSON_ArrayForEach(item, filter) {
                if (cJSON_IsString(item)) {
                    if (mg_strcmp(mg_str(priv->cfg.opts->cloud_mqtt_username), mg_str(cJSON_GetStringValue(item))) == 0) {
                        matched = true;
                        break;
                    }
                }
            }
            if (!matched) {
                goto done;
            }
        }
    } else {
        topic_prefix = mg_mprintf(IOT_AGENT_REQ_TOPIC_PREFIX, priv->cfg.opts->cloud_mqtt_username);
    }
    //dump {ServiceID}/{reqId}
    struct mg_str req_info = mg_str_n(topic.ptr + mg_str(topic_prefix).len, topic.len - mg_str(topic_prefix).len);

    //pub to rpcd topic: mg/iot-agent/{agent-id}controller/{ServiceID}/{reqId}/iot-rpcd via local-mqtt
    pub_rpcd_topic = mg_mprintf(IOT_AGENT_RPCD_CONTROLLER_TOPIC, priv->agent_id, req_info.len, req_info.ptr);
    //pub to controller topic: device/{devid}/rpc/response/{ServiceID}/{reqId} via agent-mqtt
    pub_controller_topic = mg_mprintf(IOT_AGENT_RESP_TOPIC, priv->cfg.opts->cloud_mqtt_username, req_info.len, req_info.ptr);

    //check args
    cJSON *method = cJSON_GetObjectItem(root, FIELD_METHOD);
    if (!cJSON_IsString(method)) {
        MG_ERROR(("method is not a string"));
        //response controller avoid too many req cache
        if (priv->cloud_mqtt_conn != NULL) {
            struct mg_str pubt = mg_str(pub_controller_topic);
            struct mg_mqtt_opts pub_opts;
            memset(&pub_opts, 0, sizeof(pub_opts));
            pub_opts.topic = pubt;
            pub_opts.message = data;
            pub_opts.qos = MQTT_QOS, pub_opts.retain = false;
            mg_mqtt_pub(priv->cloud_mqtt_conn, &pub_opts);
        }
        goto done;
    }

    cJSON *to = cJSON_GetObjectItem(root, FIELD_TO);
    if (cJSON_IsString(to)) { //代理请求
        rpc_agent_proxy_handler(c, req_info, root);
        goto done;
    }

    //本机请求
    struct mg_str method_value = mg_str(cJSON_GetStringValue(method));
    if ( !mg_strcmp(mg_str(IOT_METHOD_DOWNLOAD), method_value) ) { //download file
        rpc_agent_download_handler(c, mg_str(pub_controller_topic), root);
    } else if ( !mg_strcmp(mg_str(IOT_METHOD_UPLOAD), method_value) ) { //upload file
        rpc_agent_upload_handler(c, mg_str(pub_controller_topic), root);
    } else { //rpc call, mqtt proxy to rpcd
        rpc_agent_rpcd_handler(c, mg_str(pub_rpcd_topic), data);
    }

done:
    if (topic_prefix) free(topic_prefix);
    if (pub_rpcd_topic) free(pub_rpcd_topic);
    if (pub_controller_topic) free(pub_controller_topic);
    cJSON_Delete(root);

}


void timer_session_fn(void *arg) {

    struct agent_private *priv = (struct agent_private*)((struct mg_mgr*)arg)->userdata;

    uint64_t now = mg_millis();

    for (struct agent_session *next, *s = priv->sessions; s != NULL; s = next) {

        next = s->next;

        if (now > s->expire) { //timeout
            MG_INFO(("proxy agent session %lu timeout: %llu-%llu=%llu", s->proxy_id, now, s->expire, now - s->expire));
            LIST_DELETE(struct agent_session, &priv->sessions, s);
            free(s);
        }
    }

}