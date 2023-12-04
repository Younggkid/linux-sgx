/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


/**
 * File: qgs_msg_lib.h
 *
 * Description: Message and API definitions for TDX QGS messages
 *
 */
#ifndef _QGS_MSG_DEF_H_
#define _QGS_MSG_DEF_H_
#include <stdint.h>

#ifndef QGS_MSG_MK_ERROR
#define QGS_MSG_MK_ERROR(x) (0x00012000 | (x))
#endif

#pragma pack(push, 1)

/** Possible errors generated by the qgs message library. */
typedef enum _qgs_msg_error_t {
    QGS_MSG_SUCCESS = 0x0000,                                   ///< Success
    QGS_MSG_ERROR_UNEXPECTED = QGS_MSG_MK_ERROR(0x0001),        ///< Unexpected error
    QGS_MSG_ERROR_OUT_OF_MEMORY = QGS_MSG_MK_ERROR(0x0002),     ///< Not enough memory is available to complete this operation
    QGS_MSG_ERROR_INVALID_PARAMETER = QGS_MSG_MK_ERROR(0x0003), ///< The parameter is incorrect
    QGS_MSG_ERROR_INVALID_VERSION = QGS_MSG_MK_ERROR(0x0004),   ///< Unrecognized version of serialized data
    QGS_MSG_ERROR_INVALID_TYPE = QGS_MSG_MK_ERROR(0x0005),      ///< Invalid message type found
    QGS_MSG_ERROR_INVALID_SIZE = QGS_MSG_MK_ERROR(0x0006),      ///< Invalid message size found
    QGS_MSG_ERROR_INVALID_CODE = QGS_MSG_MK_ERROR(0x0007),      ///< Invalid error code

    QGS_MSG_ERROR_MAX, ///< Indicate max error to allow better translation.
} qgs_msg_error_t;

typedef enum _qgs_msg_type_t {
    GET_QUOTE_REQ = 0,
    GET_QUOTE_RESP = 1,
    GET_COLLATERAL_REQ = 2,
    GET_COLLATERAL_RESP = 3,
    QGS_MSG_TYPE_MAX
} qgs_msg_type_t;

typedef struct _qgs_msg_header_t {
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t type;
    uint32_t size;              // size of the whole message, include this header, in byte
    uint32_t error_code;        // used in response only
} qgs_msg_header_t;

typedef struct _qgs_msg_get_quote_req_t {
    qgs_msg_header_t header;    // header.type = GET_QUOTE_REQ
    uint32_t report_size;       // cannot be 0
    uint32_t id_list_size;      // length of id_list, in byte, can be 0
    uint8_t report_id_list[];   // report followed by id list
} qgs_msg_get_quote_req_t;

typedef struct _qgs_msg_get_quote_resp_s {
    qgs_msg_header_t header;    // header.type = GET_QUOTE_RESP
    uint32_t selected_id_size;  // can be 0 in case only one id is sent in request
    uint32_t quote_size;        // length of quote_data, in byte
    uint8_t id_quote[];         // selected id followed by quote
} qgs_msg_get_quote_resp_t;

typedef struct _qgs_msg_get_collateral_req_t {
    qgs_msg_header_t header;    // header.type = GET_COLLATERAL_REQ
    uint32_t fsmpc_size;        // length of fsmpc, in byte
    uint32_t pckca_size;        // length of pckca, in byte
    uint8_t fsmpc_pckca[];      // fsmpc followed by pckca
} qgs_msg_get_collateral_req_t;

typedef struct _qgs_msg_get_collateral_resp_s {
    qgs_msg_header_t header;    // header.type = GET_COLLATERAL_RESP
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t pck_crl_issuer_chain_size;
    uint32_t root_ca_crl_size;
    uint32_t pck_crl_size;
    uint32_t tcb_info_issuer_chain_size;
    uint32_t tcb_info_size;
    uint32_t qe_identity_issuer_chain_size;
    uint32_t qe_identity_size;
    uint8_t collaterals[];      // payload filled in same order as upper sizes parameters
} qgs_msg_get_collateral_resp_t;

#pragma pack(pop)

#if defined(__cplusplus)
extern "C" {
#endif
void qgs_msg_free(void *buf);

qgs_msg_error_t qgs_msg_gen_get_quote_req(
    const uint8_t *p_report, uint32_t report_size,
    const uint8_t *p_id_list, uint32_t id_list_size,
    uint8_t **pp_req, uint32_t *p_req_size);
qgs_msg_error_t qgs_msg_gen_get_collateral_req(
    const uint8_t *p_fsmpc, uint32_t fsmpc_size,
    const uint8_t *p_pckca, uint32_t pckca_size,
    uint8_t **pp_req, uint32_t *p_req_size);

qgs_msg_error_t qgs_msg_inflate_get_quote_req(
    const uint8_t *p_serialized_req, uint32_t size,
    const uint8_t **pp_report, uint32_t *p_report_size,
    const uint8_t **pp_id_list, uint32_t *p_id_list_size);
qgs_msg_error_t qgs_msg_inflate_get_collateral_req(
    const uint8_t *p_serialized_req, uint32_t size,
    const uint8_t **pp_fsmpc, uint32_t *p_fsmpc_size,
    const uint8_t **pp_pckca, uint32_t *p_pckca_size);

qgs_msg_error_t qgs_msg_gen_error_resp(
    uint32_t error_code, uint32_t type,
    uint8_t **pp_resp, uint32_t *p_resp_size);

qgs_msg_error_t qgs_msg_gen_get_quote_resp(
    const uint8_t *p_selected_id, uint32_t id_size,
    const uint8_t *p_quote, uint32_t quote_size,
    uint8_t **pp_resp, uint32_t *p_resp_size);
qgs_msg_error_t qgs_msg_gen_get_collateral_resp(
    uint16_t major_version, uint16_t minor_version,
    const uint8_t *p_pck_crl_issuer_chain, uint32_t pck_crl_issuer_chain_size,
    const uint8_t *p_root_ca_crl, uint32_t root_ca_crl_size,
    const uint8_t *p_pck_crl, uint32_t pck_crl_size,
    const uint8_t *p_tcb_info_issuer_chain, uint32_t tcb_info_issuer_chain_size,
    const uint8_t *p_tcb_info, uint32_t tcb_info_size,
    const uint8_t *p_qe_identity_issuer_chain, uint32_t qe_identity_issuer_chain_size,
    const uint8_t *p_qe_identity, uint32_t qe_identity_size,
    uint8_t **pp_resp, uint32_t *p_resp_size);

qgs_msg_error_t qgs_msg_inflate_get_quote_resp(
    const uint8_t *p_serialized_resp, uint32_t size,
    const uint8_t **pp_selected_id, uint32_t *p_id_size,
    const uint8_t **pp_quote, uint32_t *p_quote_size);
qgs_msg_error_t qgs_msg_inflate_get_collateral_resp(
    const uint8_t *p_serialized_resp, uint32_t size,
    uint16_t *p_major_version, uint16_t *p_minor_version,
    const uint8_t **pp_pck_crl_issuer_chain, uint32_t *p_pck_crl_issuer_chain_size,
    const uint8_t **pp_root_ca_crl, uint32_t *p_root_ca_crl_size,
    const uint8_t **pp_pck_crl, uint32_t *p_pck_crl_size,
    const uint8_t **pp_tcb_info_issuer_chain, uint32_t *p_tcb_info_issuer_chain_size,
    const uint8_t **pp_tcb_info, uint32_t *p_tcb_info_size,
    const uint8_t **pp_qe_identity_issuer_chain, uint32_t *p_qe_identity_issuer_chain_size,
    const uint8_t **pp_qe_identity, uint32_t *p_qe_identity_size);
uint32_t qgs_msg_get_type(const uint8_t *p_serialized_msg, uint32_t size, uint32_t *p_type);

#if defined(__cplusplus)
}
#endif

#endif