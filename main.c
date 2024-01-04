#include <iot/mongoose.h>
#include <iot/iot.h>
#include "agent.h"

//root.crt
static const char *s_ca = "-----BEGIN CERTIFICATE-----\n"
"MIIDMTCCAhkCFDAPf8BhiI979coTUPtB87KuLJ4QMA0GCSqGSIb3DQEBCwUAMFQx\n"
"CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\n"
"cm5ldCBXaWRnaXRzIFB0eSBMdGQxDTALBgNVBAMMBFJPT1QwIBcNMjIxMTA3MDI1\n"
"xIYX1VjKp9UZTdHEPQCCFPDlq9wXZczs67Rr5XRM5EpzO2OkpOFEla6M6VyMK17S\n"
"5WddwrUFKq4HmaFSW9TVTfqox42nXnRysq3Y0FeKktiLHy1KMyXYnHloZ3/QD/Vu\n"
"fWUrsPu5ECwLHrbwtXGeBBqlWXREqOc72bzJHVPi874MggMf/BHBbs6iM5TMSx+N\n"
"ZUsJZx6tGmEXKQSI6htRC8PqMVnTO4IvKEmU4yHImUKvhzjuZq530VvmF7ZMJBVg\n"
"Mhf2v1vXXBxCR+xB+r8U2rE/HXzdVcO0oa/zqOnOxzD8n0Rsns1UlcH86Wdaj6x4\n"
"7hY0aTg=\n"
"-----END CERTIFICATE-----\n";


//client.crt
static const char *s_cert = "-----BEGIN CERTIFICATE-----\n"
"MIIDNTCCAh0CFDkAgEpMXOjrLNnbytaj/XjCwgs0MA0GCSqGSIb3DQEBCwUAMFQx\n"
"CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\n"
"cm5ldCBXaWRnaXRzIFB0eSBMdGQxDTALBgNVBAMMBFJPT1QwIBcNMjIxMTA3MDMw\n"
"KfUqRARctMXc0zRXA3FtJdBV8nXzl7dBSKtquWTPLwF+lriLtsIajowVhp1KJzIv\n"
"tMcBnBq+RlGb2kSrnSLhIygkXM5UGtcsoF1yjdxD+s+VSNYxZ7JnMx1mNDc7BE9D\n"
"7kpYjbxpl87o\n"
"-----END CERTIFICATE-----\n";

//client.key
static const char *s_certkey = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEAmwp92lV9ayQkxy6oCcPQFRHETznRYqx6r7aVel27Vww7od3U\n"
"1AvBPCAZL6OSFkS2D67Gwb+0GiR5mDjsL498IflYGAyepo2uAqjxjJvj8Iudn8eN\n"
"VnkmD+NcMK5S6Gs3sSEZcVvOznbe32JRaZahOQAwcP2o9mORjnPZudu8+vYINszq\n"
"zTX9JQOvqVHkFrO+fiaAZfAg2GXaMucQzUlCoMUAGHb7jMAt6XoG/E+PIIvxRurl\n"
"wo1bzooUa1JIqVCfo8YPtGHUaCV/GB7MuVKzkvgnT/hNd3YPYLXhthtCLAXEyj5o\n"
"B9x1zMjUQrNj/1g0OStH81mD3wumIlIS5LccFM8V/DGR2ExUd6jo66MVbKZtD/Ae\n"
"kzexlQKBgCCounmn9G+C66U5kjvh+zU41zuTOKJaZ1HAgrH2Z/4fgKjsJT7nVlVL\n"
"dVzv+VUsMXasu0hoG57AR+v57fynTh0evy1XsS6JXpi6ZXnWfPoZIAl4jZztRwRT\n"
"Vc+Ax6MG57DaLSdC6Stj5d5sxI1ISYVCzFtPTesCZnsuP2GmsEVi\n"
"-----END RSA PRIVATE KEY-----\n";


static void usage(const char *prog) {
    fprintf(stderr,
            "IoT-SDK v.%s\n"
            "Usage: %s OPTIONS\n"
            "  -s ADDR  - mqtt server address, default: '%s'\n"
            "  -S ADDR  - cloud mqtt server address, default: '%s'\n"
            "  -k n     - mqtt keepalive, default: '%d'\n"
            "  -K n     - cloud mqtt timeout, default: '%d'\n"
            "  -u USER  - agent mqtt server username, default: '%s'\n"
            "  -p PASS  - agent mqtt server password, default: '%s'\n"
            "  -d ADDR  - dns server address, default: '%s'\n"
            "  -D DIR   - download file dir, default: '%s'\n"
            "  -t n     - dns server timeout, default: '%d'\n"
            "  -v LEVEL - debug level, from 0 to 4, default: %d\n",
            MG_VERSION, prog, MQTT_LISTEN_ADDR, "mqtts://mqtt.iot.hotray.cn:8883", 6, 6, "", "", "udp://119.29.29.29:53", "/tmp/download", 3, MG_LL_INFO);

    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

    struct agent_option opts = {
        .mqtt_serve_address = MQTT_LISTEN_ADDR,
        .mqtt_keepalive = 6,

        .cloud_mqtt_serve_address = "mqtts://mqtt.iot.hotray.cn:8883",
        .cloud_mqtt_keepalive = 6,

        .cloud_mqtts_ca = s_ca,
        .cloud_mqtts_cert = s_cert,
        .cloud_mqtts_certkey = s_certkey,

        .dns4_url = "udp://119.29.29.29:53",
        .dns4_timeout = 3,

        .http_download_dir = "/tmp/download",

        .debug_level = MG_LL_INFO,
	};

    // Parse command-line flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0) {
            opts.mqtt_serve_address = argv[++i];
        } else if (strcmp(argv[i], "-S") == 0) {
            opts.cloud_mqtt_serve_address = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            opts.mqtt_keepalive = atoi(argv[++i]);
            if (opts.mqtt_keepalive < 6)
                opts.mqtt_keepalive = 6;
        } else if (strcmp(argv[i], "-K") == 0) {
            opts.cloud_mqtt_keepalive = atoi(argv[++i]);
            if (opts.cloud_mqtt_keepalive < 6)
                opts.cloud_mqtt_keepalive = 6;
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
        }  else if (strcmp(argv[i], "-v") == 0) {
            opts.debug_level = atoi(argv[++i]);
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

    agent_main(&opts);

    return 0;
}