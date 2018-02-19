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


/*
 * Prototypes
 */
int parse_config_json(struct json_object *jo, bpc_handle h, void *arg);
int parse_list(struct json_object *jo, bool ipv4, bpc_handle h, void *arg);
int parse_peer_config(struct json_object *jo, struct bfd_peer_cfg *bpc,
		      bool ipv4);

int config_add(struct bfd_peer_cfg *bpc, void *arg);
int config_del(struct bfd_peer_cfg *bpc, void *arg);

int json_object_add_string(struct json_object *jo, const char *key,
			   const char *str);
int json_object_add_bool(struct json_object *jo, const char *key, bool boolean);
int json_object_add_int(struct json_object *jo, const char *key, int64_t value);

/*
 * Implementation
 */
int config_add(struct bfd_peer_cfg *bpc, void *arg __attribute__((unused)))
{
	return ptm_bfd_sess_new(bpc) == NULL;
}

int config_del(struct bfd_peer_cfg *bpc, void *arg __attribute__((unused)))
{
	return ptm_bfd_ses_del(bpc) != 0;
}

int parse_config_json(struct json_object *jo, bpc_handle h, void *arg)
{
	const char *key, *sval;
	struct json_object *jo_val;
	struct json_object_iterator joi, join;
	int error = 0;

	JSON_FOREACH (jo, joi, join) {
		key = json_object_iter_peek_name(&joi);
		jo_val = json_object_iter_peek_value(&joi);

		if (strcmp(key, "ipv4") == 0) {
			error += parse_list(jo_val, true, h, arg);
		} else if (strcmp(key, "ipv6") == 0) {
			error += parse_list(jo_val, false, h, arg);
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

	return parse_config_json(jo, config_add, NULL);
}

int parse_list(struct json_object *jo, bool ipv4, bpc_handle h, void *arg)
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
			error += (h(&bpc, arg) != 0);
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

	/* Set defaults. */
	bpc->bpc_detectmultiplier = BFD_DEFDETECTMULT;
	bpc->bpc_recvinterval = BFD_DEFREQUIREDMINRX;
	bpc->bpc_txinterval = BFD_DEFDESIREDMINTX;

	JSON_FOREACH (jo, joi, join) {
		key = json_object_iter_peek_name(&joi);
		jo_val = json_object_iter_peek_value(&joi);

		if (strcmp(key, "multihop") == 0) {
			bpc->bpc_mhop = json_object_get_boolean(jo_val);
			log_debug("\tmultihop: %s\n",
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
		} else if (strcmp(key, "detect-multiplier") == 0) {
			bpc->bpc_detectmultiplier =
				json_object_get_int64(jo_val);
			bpc->bpc_has_detectmultiplier = true;
			log_debug("\tdetect-multiplier: %llu\n",
				  bpc->bpc_detectmultiplier);
		} else if (strcmp(key, "receive-interval") == 0) {
			bpc->bpc_recvinterval = json_object_get_int64(jo_val);
			bpc->bpc_has_recvinterval = true;
			log_debug("\treceive-interval: %llu\n",
				  bpc->bpc_recvinterval);
		} else if (strcmp(key, "transmit-interval") == 0) {
			bpc->bpc_txinterval = json_object_get_int64(jo_val);
			bpc->bpc_has_txinterval = true;
			log_debug("\ttransmit-interval: %llu\n",
				  bpc->bpc_txinterval);
		} else if (strcmp(key, "create-only") == 0) {
			bpc->bpc_createonly = json_object_get_boolean(jo_val);
			log_debug("\tcreate-only: %s\n",
				  bpc->bpc_createonly ? "true" : "false");
		} else if (strcmp(key, "shutdown") == 0) {
			bpc->bpc_shutdown = json_object_get_boolean(jo_val);
			log_debug("\tshutdown: %s\n",
				  bpc->bpc_shutdown ? "true" : "false");
		} else {
			sval = json_object_get_string(jo_val);
			log_warning("%s:%d invalid configuration: '%s: %s'\n",
				    __FUNCTION__, __LINE__, key, sval);
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

	return parse_config_json(jo, config_add, NULL);
}

int config_request_del(const char *jsonstr)
{
	struct json_object *jo;

	jo = json_tokener_parse(jsonstr);
	if (jo == NULL)
		return -1;

	return parse_config_json(jo, config_del, NULL);
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

char *config_notify(bfd_session *bs)
{
	struct json_object *resp;
	char *jsonstr;

	resp = json_object_new_object();
	if (resp == NULL)
		return NULL;

	json_object_add_string(resp, "op", BCM_NOTIFY_PEER_STATUS);

	/* Add peer 'key' information. */
	json_object_add_bool(resp, "ipv6",
			     BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6));
	json_object_add_bool(resp, "multihop",
			     BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH));
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)) {
		if (json_object_add_string(resp, "peer-address",
					   satostr(&bs->mhop.peer))
		    == -1)
			return NULL;
		if (json_object_add_string(resp, "local-address",
					   satostr(&bs->mhop.local))
		    == -1)
			return NULL;
		if (strlen(bs->mhop.vrf_name) > 0) {
			json_object_add_string(resp, "vrf-name",
					       bs->mhop.vrf_name);
		}
	} else {
		if (json_object_add_string(resp, "peer-address",
					   satostr(&bs->shop.peer))
		    == -1)
			return NULL;
		if (strlen(bs->shop.port_name) > 0) {
			json_object_add_string(resp, "local-interface",
					       bs->shop.port_name);
		}
	}

	/* Add status information */
	json_object_add_int(resp, "id", bs->discrs.my_discr);
	json_object_add_int(resp, "remote-id", bs->discrs.my_discr);

	switch (bs->ses_state) {
	case PTM_BFD_UP:
		json_object_add_string(resp, "state", "up");
		break;
	case PTM_BFD_ADM_DOWN:
		json_object_add_string(resp, "state", "adm-down");
		break;
	case PTM_BFD_DOWN:
		json_object_add_string(resp, "state", "down");
		break;
	case PTM_BFD_INIT:
		json_object_add_string(resp, "state", "init");
		break;

	default:
		json_object_add_string(resp, "state", "unknown");
		break;
	}

	/* Generate JSON response. */
	jsonstr = strdup(
		json_object_to_json_string_ext(resp, JSON_C_TO_STRING_PRETTY));
	json_object_put(resp);

	return jsonstr;
}

char *config_notify_config(const char *op, bfd_session *bs)
{
	struct json_object *resp;
	char *jsonstr;

	resp = json_object_new_object();
	if (resp == NULL)
		return NULL;

	json_object_add_string(resp, "op", op);

	/* Add peer 'key' information. */
	json_object_add_bool(resp, "ipv6",
			     BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6));
	json_object_add_bool(resp, "multihop",
			     BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH));
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)) {
		if (json_object_add_string(resp, "peer-address",
					   satostr(&bs->mhop.peer))
		    == -1)
			return NULL;
		if (json_object_add_string(resp, "local-address",
					   satostr(&bs->mhop.local))
		    == -1)
			return NULL;
		if (strlen(bs->mhop.vrf_name) > 0) {
			json_object_add_string(resp, "vrf-name",
					       bs->mhop.vrf_name);
		}
	} else {
		if (json_object_add_string(resp, "peer-address",
					   satostr(&bs->shop.peer))
		    == -1)
			return NULL;
		if (strlen(bs->shop.port_name) > 0) {
			json_object_add_string(resp, "local-interface",
					       bs->shop.port_name);
		}
	}

	/* On peer deletion we don't need to add any additional information. */
	if (strcmp(op, BCM_NOTIFY_CONFIG_DELETE) == 0) {
		goto skip_config;
	}

	json_object_add_int(resp, "detect-multiplier", bs->detect_mult);
	json_object_add_int(resp, "receive-interval",
			    bs->timers.required_min_rx);
	json_object_add_int(resp, "transmit-interval", bs->up_min_tx);
	json_object_add_bool(resp, "shutdown",
			     BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN));

skip_config:
	/* Generate JSON response. */
	jsonstr = strdup(
		json_object_to_json_string_ext(resp, JSON_C_TO_STRING_PRETTY));
	json_object_put(resp);

	return jsonstr;
}

int config_notify_request(struct bfd_control_socket *bcs, const char *jsonstr,
			  bpc_handle bh)
{
	struct json_object *jo;

	jo = json_tokener_parse(jsonstr);
	if (jo == NULL)
		return -1;

	return parse_config_json(jo, bh, bcs);
}


/*
 * JSON helper functions
 */
int json_object_add_string(struct json_object *jo, const char *key,
			   const char *str)
{
	struct json_object *jon;

	jon = json_object_new_string(str);
	if (jon == NULL) {
		json_object_put(jon);
		return -1;
	}

	json_object_object_add(jo, key, jon);
	return 0;
}

int json_object_add_bool(struct json_object *jo, const char *key, bool boolean)
{
	struct json_object *jon;

	jon = json_object_new_boolean(boolean);
	if (jon == NULL) {
		json_object_put(jon);
		return -1;
	}

	json_object_object_add(jo, key, jon);
	return 0;
}

int json_object_add_int(struct json_object *jo, const char *key, int64_t value)
{
	struct json_object *jon;

	jon = json_object_new_int64(value);
	if (jon == NULL) {
		json_object_put(jon);
		return -1;
	}

	json_object_object_add(jo, key, jon);
	return 0;
}
