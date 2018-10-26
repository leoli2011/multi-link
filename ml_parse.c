#include <stdio.h>
#include <syslog.h>
#include <yaml.h>
#include "ml_parse.h"
#include "multilink.h"

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
wan_if_t wan_if_list[10];

int parse_interface_info(yaml_parser_t *parser, wan_if_t *wif)
{
    yaml_token_t  token;
    char *datap = NULL;
    int state = 0;
    int i = 0;

    do {
        yaml_parser_scan(parser, &token);
        switch(token.type)
        {

        case YAML_KEY_TOKEN:
            state = 0;
            break;
        case YAML_VALUE_TOKEN:
            state = 1;
            break;

        case YAML_BLOCK_END_TOKEN:
            wif++;
            i++;
            break;

        case YAML_SCALAR_TOKEN: {
            char *tk = (char *)token.data.scalar.value;
            int len = 0;
            if (state == 0) {
                if (strcmp(tk, "ifname") == 0) {
                    datap = wif->ifname;
                } else if (strcmp(tk, "table") == 0) {
                    datap = wif->table;
                } else if (strcmp(tk, "weight") == 0) {
                    datap = wif->weight;
                }
            } else if (state == 1) {
                snprintf(datap, 20, "%s", tk);
            }
            break;

        }
        default:
          printf("Got token of type %d\n", token.type);
          break;
        }
        if(token.type != YAML_BLOCK_END_TOKEN)
          yaml_token_delete(&token);
    } while(i < get_wan_cnt());
          yaml_token_delete(&token);

    return 0;
}

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

    if (!yaml_parser_initialize(&parser)) {
        syslog(LOG_ERR, "Failed to initialize parser!\n");
        return -1;
    }

    if (fh == NULL) {
        syslog(LOG_ERR, "Failed to open file!\n");
        return -1;
    }

    yaml_parser_set_input_file(&parser, fh);

    do {
        yaml_parser_scan(&parser, &token);
        switch(token.type)
        {

            case YAML_STREAM_START_TOKEN:
            case YAML_STREAM_END_TOKEN:
                break;

            case YAML_KEY_TOKEN:
                expect_token = 1;
                break;

            case YAML_VALUE_TOKEN:
                expect_value = 1;
                break;

            case YAML_BLOCK_SEQUENCE_START_TOKEN:
                level = 1;
                break;

            case YAML_BLOCK_ENTRY_TOKEN:
                app_index++;
                break;

            case YAML_BLOCK_END_TOKEN:
                if (app_index >= 0 && app_index < 10) {
                    strncpy(app_info[app_index].name, app_lists[0].value, sizeof(app_info[app_index].name));
                    strncpy(app_info[app_index].ip, app_lists[1].value, sizeof(app_info[app_index].ip));
                    strncpy(app_info[app_index].port, app_lists[2].value, sizeof(app_info[app_index].ip));
                }

                break;

            case YAML_BLOCK_MAPPING_START_TOKEN:
                break;

            case YAML_SCALAR_TOKEN:
                tk = (char *)token.data.scalar.value;
                if (strcmp(tk, "WAN-interface") == 0) {
                    parse_interface_info(&parser, &wan_if_list[0]);
                    for (int i = 0; i < get_wan_cnt(); i++) {
                        syslog(LOG_NOTICE, "wif name=%s, table=%s, weight %s \n",
                                wan_if_list[i].ifname, wan_if_list[i].table, wan_if_list[i].weight);
                    }

                    break;
                }

                if (level == 0 && expect_token == 1) {
                    for (unsigned int i = 0; i < sizeof(g_conf)/sizeof(g_conf[0]); i++) {
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
                    for (unsigned int i = 0; i < sizeof(app_lists)/sizeof(app_lists[0]); i++) {
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
            case YAML_DOCUMENT_END_TOKEN:
                break;

            default:
                syslog(LOG_NOTICE, "Got token of type %d\n", token.type);
        }

        if(token.type != YAML_STREAM_END_TOKEN)
            yaml_token_delete(&token);
    } while(token.type != YAML_STREAM_END_TOKEN);
    yaml_token_delete(&token);

    yaml_parser_delete(&parser);

    for (unsigned int i = 0; i < sizeof(g_conf)/sizeof(g_conf[0]); i++) {
        syslog(LOG_NOTICE, "g_conf name =%s value=%s\n", g_conf[i].name, g_conf[i].value);
    }

    for (int i = 1; i <= app_index; i++) {
        syslog(LOG_NOTICE, "app_info name =%s ip=%s port=%s\n", app_info[i].name, app_info[i].ip, app_info[i].port);
    }

    fclose(fh);

    return 0;
}
