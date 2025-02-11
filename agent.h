#ifndef __IOT_AGENT_H__
#define __IOT_AGENT_H__

#include <iot/mongoose.h>

#define IOT_AGENT_DEVICE_ALL "$all"
#define IOT_AGENT_DEVICE_ALL_PREFIX "device/$all"
#define FIELD_FILTER "filter"
struct agent_option {

    const char *mqtt_serve_address;      //mqtt 服务端口
    int mqtt_keepalive;                  //mqtt 保活间隔

    const char *cloud_mqtt_client_id;    //cloud mqtt client id
    const char *cloud_mqtt_serve_address;
    const char *cloud_mqtt_username;
    const char *cloud_mqtt_password;
    int cloud_mqtt_keepalive;

    const char *cloud_mqtts_ca;
    const char *cloud_mqtts_cert;
    const char *cloud_mqtts_certkey;

    const char *dns4_url;
    int dns4_timeout;

    const char *http_download_dir;         //download file store in
    int debug_level;
    const char *callback_lua;
};

struct agent_config {
    struct agent_option *opts;
};

struct agent_session {
    struct agent_session *next;
    unsigned long proxy_id;
    uint64_t expire;
    char req_info[MQTT_MAX_TOPIC_LEN];
};

struct agent_private {

    struct agent_config cfg;

    struct mg_mgr mgr;
    struct mg_fs *fs;

    struct mg_connection *mqtt_conn;
    uint64_t ping_active;
    uint64_t pong_active;

    struct mg_connection *cloud_mqtt_conn;
    uint64_t cloud_ping_active;
    uint64_t cloud_pong_active;

    char agent_id[21]; //id len 20 + 0

    uint64_t proxy_id;

    struct agent_session *sessions;

    int registered;
    uint64_t disconnected_check_times;


};

int agent_main(void *user_options);


#endif