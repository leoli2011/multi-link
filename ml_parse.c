#include <stdio.h>
#include <syslog.h>
#include <yaml.h>
#include "ml_parse.h"

struct global_config g_conf[] =  {
    {.name = "config-version"},
    {.name = "schedule_policy"},
    {.name = "country"},
};

struct app_list app_lists[] = {
    {.name = "app_name"},
    {.name = "server"},
    {.name = "port"},
};

free_app_info_t app_info[10];

int parse_conf(FILE *f)
{
    FILE *fh = f;
    int level = 0;
    int expect_token = 0;
    int expect_value = 0;
    char *tk = NULL;
    int app_index = 0;
    char *store_value = NULL;
    yaml_parser_t parser;
    yaml_token_t  token;

    if(!yaml_parser_initialize(&parser))
        syslog(LOG_ERR, "Failed to initialize parser!\n");

    if(fh == NULL)
        syslog(LOG_ERR, "Failed to open file!\n");

    yaml_parser_set_input_file(&parser, fh);

    do {
        yaml_parser_scan(&parser, &token);
        switch(token.type)
        {

            case YAML_STREAM_START_TOKEN:
                syslog(LOG_DEBUG, "STREAM START");
                break;

            case YAML_STREAM_END_TOKEN:
                syslog(LOG_NOTICE, "STREAM END");
                break;

            case YAML_KEY_TOKEN:
                syslog(LOG_NOTICE, "(Key token)   ");
                expect_token = 1;
                break;

            case YAML_VALUE_TOKEN:
                expect_value = 1;
                syslog(LOG_NOTICE, "(Value token) ");
                break;

            case YAML_BLOCK_SEQUENCE_START_TOKEN:
                syslog(LOG_NOTICE, "<b>Start Block (Sequence)</b>");
                level = 1;
                break;

            case YAML_BLOCK_ENTRY_TOKEN:
                syslog(LOG_NOTICE, "<b>Start Block (Entry)</b>");
                app_index++;
                break;

            case YAML_BLOCK_END_TOKEN:
                if (app_index >= 0 && app_index < 10) {
                    strncpy(app_info[app_index].name, app_lists[0].value, sizeof(app_info[app_index].name));
                    strncpy(app_info[app_index].ip, app_lists[1].value, sizeof(app_info[app_index].ip));
                    strncpy(app_info[app_index].port, app_lists[2].value, sizeof(app_info[app_index].ip));
                }

                syslog(LOG_NOTICE, "<b>End block</b>");
                break;

            case YAML_BLOCK_MAPPING_START_TOKEN:
                syslog(LOG_NOTICE, "[Block mapping]");
                break;

            case YAML_SCALAR_TOKEN:
                syslog(LOG_NOTICE, "scalar %s \n", token.data.scalar.value);
                tk = token.data.scalar.value;
                if (level == 0 && expect_token == 1) {
                    for (int i = 0; i < sizeof(g_conf)/sizeof(g_conf[0]); i++) {
                        if (strcmp(tk, g_conf[i].name) == 0) {
                            store_value = g_conf[i].value;
                        }
                    }
                    if (store_value == NULL) {
                        syslog(LOG_NOTICE, "Unrecognised key:%s", tk);
                        break;
                    }
                    expect_token = 0;
                } else if (level == 0 && expect_value == 1 && store_value != NULL) {
                    snprintf(store_value, 64, "%s", tk);
                    expect_value = 0;
                    store_value = NULL;
                } else if (level == 1 && expect_token == 1) {
                    for (int i = 0; i < sizeof(app_lists)/sizeof(app_lists[0]); i++) {
                        if (strcmp(tk, app_lists[i].name) == 0) {
                            store_value = app_lists[i].value;
                            syslog(LOG_NOTICE, "level=%d app_lists[%d].name=%s, store_value=%s \n",
                                    level, i, app_lists[i].name, store_value);
                        }
                    }
                    if (store_value == NULL) {
                        break;
                    }
                    expect_token = 0;
                } else if (level == 1 && expect_value == 1 && store_value != NULL) {
                    snprintf(store_value, 64, "%s", tk);
                    expect_value = 0;
                    syslog(LOG_NOTICE, "level=%d store_value=%s \n", level, store_value);
                    store_value = NULL;
                }

                break;

            case YAML_DOCUMENT_START_TOKEN:
                syslog(LOG_NOTICE, "[Start Document]");
                break;

            case YAML_DOCUMENT_END_TOKEN:
                syslog(LOG_NOTICE, "[End document]");
                break;

            default:
                syslog(LOG_NOTICE, "Got token of type %d\n", token.type);
        }

        if(token.type != YAML_STREAM_END_TOKEN)
            yaml_token_delete(&token);
    } while(token.type != YAML_STREAM_END_TOKEN);
    yaml_token_delete(&token);

    yaml_parser_delete(&parser);

    for (int i = 0; i < sizeof(g_conf)/sizeof(g_conf[0]); i++) {
        syslog(LOG_NOTICE, "g_conf name =%s value=%s\n", g_conf[i].name, g_conf[i].value);
    }

    for (int i = 1; i <= app_index; i++) {
        syslog(LOG_NOTICE, "app_info name =%s ip=%s port=%s\n", app_info[i].name, app_info[i].ip, app_info[i].port);
    }

    fclose(fh);

    return 0;
}
