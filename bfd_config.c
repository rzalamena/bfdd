/*********************************************************************
 * Copyright 2017 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is licensed to You under the Eclipse Public License (EPL);
 * You may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 *
 * bfdd.c implements the BFD daemon
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <json-c/json.h>

#include <string.h>

#include "bfd.h"

/*
 * Definitions
 */
#define JSON_FOREACH(jo, joi, join)                                            \
	/* struct json_object *jo; */                                          \
	/* struct json_object_iterator joi; */                                 \
	/* struct json_object_iterator join; */                                \
	for ((joi) = json_object_iter_begin((jo)),                             \
	    (join) = json_object_iter_end((jo));                               \
	     json_object_iter_equal(&(joi), &(join)) == 0;                     \
	     json_object_iter_next(&(joi)))

typedef void (*bpc_handle)(struct bfd_peer_cfg *);


/*
 * Prototypes
 */
int parse_config_json(struct json_object *jo, bpc_handle h);
int parse_list(struct json_object *jo, bool ipv4, bpc_handle h);
int parse_peer_config(struct json_object *jo, struct bfd_peer_cfg *bpc,
		      bool ipv4);

void config_add(struct bfd_peer_cfg *bpc);
void config_del(struct bfd_peer_cfg *bpc);


/*
 * Implementation
 */
void config_add(struct bfd_peer_cfg *bpc)
{
	ptm_bfd_sess_new(bpc);
}

void config_del(struct bfd_peer_cfg *bpc)
{
	ptm_bfd_ses_del(bpc);
}

int parse_config_json(struct json_object *jo, bpc_handle h)
{
	const char *key, *sval;
	struct json_object *jo_val;
	struct json_object_iterator joi, join;
	int error = 0;

	JSON_FOREACH (jo, joi, join) {
		key = json_object_iter_peek_name(&joi);
		jo_val = json_object_iter_peek_value(&joi);

		if (strcmp(key, "ipv4") == 0) {
			error += parse_list(jo_val, true, h);
		} else if (strcmp(key, "ipv6") == 0) {
			error += parse_list(jo_val, false, h);
		} else {
			sval = json_object_get_string(jo_val);
			log_warning("%s:%d invalid configuration: %s\n",
				    __FUNCTION__, __LINE__, sval);
			error++;
		}
	}

	return error;
}

int parse_config(const char *fname)
{
	struct json_object *jo;

	jo = json_object_from_file(fname);
	if (jo == NULL)
		log_fatal("failed to load configuration from %s\n", fname);

	return parse_config_json(jo, config_add);
}

int parse_list(struct json_object *jo, bool ipv4, bpc_handle h)
{
	struct json_object *jo_val;
	struct bfd_peer_cfg bpc;
	int allen, idx;
	int error = 0, result;

	allen = json_object_array_length(jo);
	log_debug("ipv%s peers %d:\n", ipv4 ? "4" : "6", allen);
	for (idx = 0; idx < allen; idx++) {
		jo_val = json_object_array_get_idx(jo, idx);
		result = parse_peer_config(jo_val, &bpc, ipv4);
		error += result;
		if (result == 0)
			h(&bpc);
	}

	return error;
}

int parse_peer_config(struct json_object *jo, struct bfd_peer_cfg *bpc,
		      bool ipv4)
{
	const char *key, *sval;
	struct json_object *jo_val;
	struct json_object_iterator joi, join;
	int family_type = (ipv4) ? AF_INET : AF_INET6;
	int error = 0;

	memset(bpc, 0, sizeof(*bpc));
	bpc->bpc_ipv4 = ipv4;
	log_debug("\tpeer: %s\n", ipv4 ? "ipv4" : "ipv6");

	JSON_FOREACH (jo, joi, join) {
		key = json_object_iter_peek_name(&joi);
		jo_val = json_object_iter_peek_value(&joi);

		if (strcmp(key, "multihop") == 0) {
			bpc->bpc_mhop = json_object_get_boolean(jo_val);
			log_debug("\tmhop: %s\n",
				  bpc->bpc_mhop ? "true" : "false");
		} else if (strcmp(key, "peer-address") == 0) {
			sval = json_object_get_string(jo_val);
			if (strtosa(sval, &bpc->bpc_peer) != 0
			    && bpc->bpc_peer.sa_sin.sin_family == family_type) {
				log_info(
					"%s:%d failed to parse peer-address '%s'",
					__FUNCTION__, __LINE__, sval);
				error++;
			}
			log_debug("\tpeer-address: %s\n", sval);
		} else if (strcmp(key, "local-address") == 0) {
			sval = json_object_get_string(jo_val);
			if (strtosa(sval, &bpc->bpc_local) != 0
			    && bpc->bpc_peer.sa_sin.sin_family == family_type) {
				log_info(
					"%s:%d failed to parse local-address '%s'",
					__FUNCTION__, __LINE__, sval);
				error++;
			}
			log_debug("\tlocal-address: %s\n", sval);
		} else if (strcmp(key, "local-interface") == 0) {
			sval = json_object_get_string(jo_val);
			strxcpy(bpc->bpc_localif, sval,
				sizeof(bpc->bpc_localif));
			bpc->bpc_has_localif = true;
			log_debug("\tlocal-interface: %s\n", sval);
		} else if (strcmp(key, "vxlan") == 0) {
			bpc->bpc_vxlan = json_object_get_int64(jo_val);
			bpc->bpc_has_vxlan = true;
			log_debug("\tvxlan: %ld\n", bpc->bpc_vxlan);
		} else if (strcmp(key, "vrf-name") == 0) {
			sval = json_object_get_string(jo_val);
			strxcpy(bpc->bpc_vrfname, sval,
				sizeof(bpc->bpc_vrfname));
			bpc->bpc_has_vrfname = true;
			log_debug("\tvrf-name: %s\n", sval);
		} else {
			sval = json_object_get_string(jo_val);
			log_warning("%s:%d invalid configuration: %s\n",
				    __FUNCTION__, __LINE__, sval);
			error++;
		}
	}

	return error;
}

/*
 * Control socket JSON parsing.
 */
int config_request_add(const char *jsonstr)
{
	struct json_object *jo;

	jo = json_tokener_parse(jsonstr);
	if (jo == NULL)
		return -1;

	return parse_config_json(jo, config_add);
}

int config_request_del(const char *jsonstr)
{
	struct json_object *jo;

	jo = json_tokener_parse(jsonstr);
	if (jo == NULL)
		return -1;

	return parse_config_json(jo, config_del);
}

char *config_response(const char *status, const char *error)
{
	struct json_object *resp, *jo;
	char *jsonstr;

	resp = json_object_new_object();
	if (resp == NULL)
		return NULL;

	/* Add 'status' response key. */
	jo = json_object_new_string(status);
	if (jo == NULL) {
		json_object_put(resp);
		return NULL;
	}

	json_object_object_add(resp, "status", jo);

	/* Add 'error' response key. */
	if (error != NULL) {
		jo = json_object_new_string(error);
		if (jo == NULL) {
			json_object_put(resp);
			return NULL;
		}

		json_object_object_add(resp, "error", jo);
	}

	/* Generate JSON response. */
	jsonstr = strdup(
		json_object_to_json_string_ext(resp, JSON_C_TO_STRING_PRETTY));
	json_object_put(resp);

	return jsonstr;
}
