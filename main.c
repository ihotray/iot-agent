#include <iot/mongoose.h>
#include <iot/iot.h>
#include "agent.h"


#define CA "/www/iot/certs/ca"
#define CERT "/www/iot/certs/client.cert"
#define KEY "/www/iot/certs/client.key"

#define LUA_CALLBACK_SCRIPT "/www/iot/handler/iot-agent.lua"

static void usage(const char *prog) {
    fprintf(stderr,
        "IoT-SDK v.%s\n"
        "Usage: %s OPTIONS\n"
        "  -s ADDR  - mqtt server address, default: '%s'\n"
        "  -S ADDR  - cloud mqtt server address, default: '%s'\n"
        "  -a n     - local mqtt keepalive, default: %d\n"
        "  -A n     - cloud mqtt keepalive, default: %d\n"
        "  -C CA    - ca content or file path for cloud mqtts communication, default: '%s'\n"
        "  -c CERT  - cert content or file path for cloud mqtts communication, default: '%s'\n"
        "  -k KEY   - key content or file path for cloud mqtts communication, default: '%s'\n"
        "  -u USER  - agent mqtt server username, default: '%s'\n"
        "  -p PASS  - agent mqtt server password, default: '%s'\n"
        "  -d ADDR  - dns server address, default: '%s'\n"
        "  -D DIR   - download file dir, default: '%s'\n"
        "  -t n     - dns server timeout, default: %d\n"
        "  -x PATH  - agent connected/disconnected callback script, default: '%s'\n"
        "  -v LEVEL - debug level, from 0 to 4, default: %d\n",
        MG_VERSION, prog, MQTT_LISTEN_ADDR, "mqtts://mqtt.iot.hotray.cn:8883", 6, 6, \
        CA, CERT, KEY, "", "", "udp://119.29.29.29:53", "/tmp/download", 6, LUA_CALLBACK_SCRIPT, MG_LL_INFO);

    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

    struct agent_option opts = {
        .mqtt_serve_address = MQTT_LISTEN_ADDR,
        .mqtt_keepalive = 6,

        .cloud_mqtt_serve_address = "mqtts://mqtt.iot.hotray.cn:8883",
        .cloud_mqtt_keepalive = 6,

        .cloud_mqtts_ca = CA,
        .cloud_mqtts_cert = CERT,
        .cloud_mqtts_certkey = KEY,

        .dns4_url = "udp://119.29.29.29:53",
        .dns4_timeout = 6,

        .http_download_dir = "/tmp/download",

        .callback_lua = LUA_CALLBACK_SCRIPT,
        .debug_level = MG_LL_INFO,
    };

    // Parse command-line flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0) {
            opts.mqtt_serve_address = argv[++i];
        } else if (strcmp(argv[i], "-S") == 0) {
            opts.cloud_mqtt_serve_address = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0) {
            opts.mqtt_keepalive = atoi(argv[++i]);
            if (opts.mqtt_keepalive < 6)
                opts.mqtt_keepalive = 6;
        } else if (strcmp(argv[i], "-A") == 0) {
            opts.cloud_mqtt_keepalive = atoi(argv[++i]);
            if (opts.cloud_mqtt_keepalive < 6)
                opts.cloud_mqtt_keepalive = 6;
        } else if (strcmp(argv[i], "-C") == 0) {
            opts.cloud_mqtts_ca = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0) {
            opts.cloud_mqtts_cert = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            opts.cloud_mqtts_certkey = argv[++i];
        } else if (strcmp(argv[i], "-u") == 0) {
            opts.cloud_mqtt_username = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0) {
            opts.cloud_mqtt_password = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0) {
            opts.dns4_url = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0) {
            opts.dns4_timeout = atoi(argv[++i]);
            if (opts.dns4_timeout < 3)
                opts.dns4_timeout = 3;
        } else if (strcmp(argv[i], "-D") == 0) {
            opts.http_download_dir = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            opts.debug_level = atoi(argv[++i]);
        } else if( strcmp(argv[i], "-x") == 0) {
            opts.callback_lua = argv[++i];
        } else {
            usage(argv[0]);
        }
    }

    if (opts.cloud_mqtt_username == NULL) {
        usage(argv[0]);
    }

    MG_INFO(("IoT-SDK version  : v%s", MG_VERSION));
    MG_INFO(("Username         : %s", opts.cloud_mqtt_username));
    MG_INFO(("DNSv4 Server     : %s", opts.dns4_url));
    MG_INFO(("Lua handler path : %s", opts.callback_lua));

    agent_main(&opts);

    return 0;
}