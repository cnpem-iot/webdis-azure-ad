#include "acl.h"
#include "client.h"
#include "cmd.h"
#include "conf.h"
#include "http.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <evhttp.h>
#include <jansson.h>
#include <netinet/in.h>
#include <string.h>

struct memory {
  char *response;
  size_t size;
};

static size_t cb(void *data, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct memory *mem = (struct memory *)userp;

  char *ptr = realloc(mem->response, mem->size + realsize + 1);
  if (ptr == NULL)
    return 0; /* out of memory! */

  mem->response = ptr;
  memcpy(&(mem->response[mem->size]), data, realsize);
  mem->size += realsize;
  mem->response[mem->size] = 0;

  return realsize;
}

static int auth_org_ms(const char *token, const char *tenant) {
  CURLcode ret;
  CURL *hnd;
  struct curl_slist *slist;

  char *header = (char *)malloc(4096 * sizeof(char));
  snprintf(header, 4096, "Authorization: Bearer %s", token);

  slist = NULL;
  slist = curl_slist_append(slist, header);

  struct memory chunk = {0};

  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
  curl_easy_setopt(hnd, CURLOPT_URL, "https://graph.microsoft.com/v1.0/organization");
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.74.0");
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, cb);
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&chunk);

  ret = curl_easy_perform(hnd);

  long http_code = 0;
  curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup(hnd);
  hnd = NULL;
  curl_slist_free_all(slist);
  slist = NULL;
  free(header);

  json_t *parsed_rep;
  json_t *nested_vals;
  json_error_t error;

  parsed_rep = json_loads(chunk.response, 0, &error);

  if (parsed_rep) {
    if (http_code == 200 && ret == CURLE_OK) {
      nested_vals = json_array_get(json_object_get(parsed_rep, "value"), 0);
      return strcmp(tenant, json_string_value(json_object_get(nested_vals, "id"))) == 0;
    }
  } else {
    fprintf(stderr, "json error on line %d: %s\n", error.line, error.text);
  }

  return 0;
}

static int auth_ms(const char *token, const char *tenant, char *username) {
  CURLcode ret;
  CURL *hnd;
  struct curl_slist *slist;

  char *header = (char *)malloc(4096 * sizeof(char));
  snprintf(header, 4096, "Authorization: Bearer %s", token);

  slist = NULL;
  slist = curl_slist_append(slist, header);

  struct memory chunk = {0};

  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
  curl_easy_setopt(hnd, CURLOPT_URL, "https://graph.microsoft.com/v1.0/me");
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.74.0");
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, cb);
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&chunk);

  ret = curl_easy_perform(hnd);

  long http_code = 0;
  curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

  curl_easy_cleanup(hnd);
  hnd = NULL;
  curl_slist_free_all(slist);
  slist = NULL;
  free(header);

  json_t *parsed_rep;
  json_error_t error;

  parsed_rep = json_loads(chunk.response, 0, &error);

  if (parsed_rep) {
    if (http_code == 200 && ret == CURLE_OK) {
      /* Compare tenant ID from token and declared tenant ID */
      if (auth_org_ms(token, tenant)) {
        memcpy(username, json_string_value(json_object_get(parsed_rep, "mail")),128);
        return 0;
      }
    }
  } else {
    fprintf(stderr, "json error on line %d: %s\n", error.line, error.text);
  }

  return 1;
}

int acl_match_client(struct acl *a, struct http_client *client, in_addr_t *ip) {
  /* check Azure AD Auth, obtains user info */
  const char *auth;
  char username[146] = "";

  auth = client_get_header(client, "Authorization");
  if (a->tenant_id) {
    if (auth && strncasecmp(auth, "Bearer ", 7) == 0) {
      if (auth_ms(auth + 7, a->tenant_id, username)) {
        return 0;
      }
    } else { /* no auth sent, required to match this ACL */
      return 0;
    }
  }

  /* CIDR check. Comparision structure slightly altered from the original */
  if (a->cidr.enabled == 0 ||
      ((*ip) & a->cidr.mask) == (a->cidr.subnet & a->cidr.mask)) {
    /* Don't log for non-auths */
    if (username[0] != '\0') {
      strncat(username, " authenticated", 16);
      slog(client->s, WEBDIS_NOTICE, username, strlen(username));
    }
    return 1;
  }

  return 0;
}

int acl_allow_command(struct cmd *cmd, struct conf *cfg,
                      struct http_client *client) {

  char *always_off[] = {"MULTI", "EXEC", "WATCH", "DISCARD", "SELECT"};

  unsigned int i;
  int authorized = 1;
  struct acl *a;

  in_addr_t client_addr;

  const char *cmd_name;
  size_t cmd_len;

  if (cmd->count == 0) {
    return 0;
  }

  cmd_name = cmd->argv[0];
  cmd_len = cmd->argv_len[0];

  /* some commands are always disabled, regardless of the config file. */
  for (i = 0; i < sizeof(always_off) / sizeof(always_off[0]); ++i) {
    if (strncasecmp(always_off[i], cmd_name, cmd_len) == 0) {
      return 0;
    }
  }

  /* find client's address */
  client_addr = ntohl(client->addr);

  /* go through permissions */
  for (a = cfg->perms; a; a = a->next) {

    if (!acl_match_client(a, client, &client_addr))
      continue; /* match client */

    /* go through authorized commands */
    for (i = 0; i < a->enabled.count; ++i) {
      if (strncasecmp(a->enabled.commands[i], cmd_name, cmd_len) == 0) {
        authorized = 1;
      }
      if (strncasecmp(a->enabled.commands[i], "*", 1) == 0) {
        authorized = 1;
      }
    }

    /* go through unauthorized commands */
    for (i = 0; i < a->disabled.count; ++i) {
      if (strncasecmp(a->disabled.commands[i], cmd_name, cmd_len) == 0) {
        authorized = 0;
      }
      if (strncasecmp(a->disabled.commands[i], "*", 1) == 0) {
        authorized = 0;
      }
    }
  }

  return authorized;
}
