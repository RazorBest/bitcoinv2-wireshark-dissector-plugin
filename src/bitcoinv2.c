#define WS_LOG_DOMAIN "bitcoinv2"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// Contains WS_VERSION and WS_VERSION_NUM
#include <ws_version.h>

#define WS_VERSION_NUM(maj, min, mic) (((maj) * 10000) + ((min) * 100) + (mic))
#define WS_VERSION WS_VERSION_NUM(WIRESHARK_VERSION_MAJOR, \
                                  WIRESHARK_VERSION_MINOR, \
                                  WIRESHARK_VERSION_MICRO)

// Top-level header: wireshark.h arrived in 3.7/4.0
#if WS_VERSION >= WS_VERSION_NUM(4, 0, 0)
  #include <wireshark.h>
#else
  #ifdef HAVE_CONFIG_H
    #include "config.h"
  #endif
  #include <stdbool.h>
  #include <stdint.h>
  #include <glib.h>
  #include <ws_symbol_export.h>
  #include <ws_attributes.h>
#endif

#include <epan/column-utils.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/exceptions.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/wmem_scopes.h>

#if defined(__has_include)
#if __has_include(<wsutil/plugins.h>)
#include <wsutil/plugins.h>  // WS_PLUGIN_DESC_DISSECTOR (newer releases only)
#endif
#endif

#ifndef _U_
  #if defined(__GNUC__) || defined(__clang__)
    #define _U_ __attribute__((unused))
  #else
    #define _U_
  #endif
#endif

/*
 * Use WS_DLL_PUBLIC and WS_DLL_PUBLIC_DEF for any symbol that we want to export
 * (i.e. Wireshark will have access to them).
 *
 * WS_DLL_PUBLIC_DEF is for definitions.
 * WS_DLL_PUBLIC is for declarations.
 */

WS_DLL_PUBLIC_DEF const char plugin_version[] = "0.0.1";
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
#ifdef WS_PLUGIN_DESC_DISSECTOR
WS_DLL_PUBLIC uint32_t plugin_describe(void);
#endif

// Check https://www.wireshark.org/docs/relnotes/wireshark-4.4.0.html
// The tvb_get_guintX and tvb_get_gintX functions in the tvbuff API have been
// renamed to tvb_get_uintX and tvb_get_intX (the GLib-style "g" has been removed).
#if WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR < 4
#define tvb_get_uint8 tvb_get_guint8
#endif

// Bytes that identify the version message in v2:
// Three bytes little-endian length, one byte BIP-324 header, one byte compression indicator
static const uint8_t version_ident[] = {0x73, 0x00, 0x00, 0x00, 0x00, 'v',  'e',  'r', 's',
                                        'i',  'o',  'n',  0x00, 0x00, 0x00, 0x00, 0x00};

#define VERSION_IDENT_LEN          (sizeof(version_ident))
#define VERSION_IDENT_SEARCH_LIMIT 5000

#define ELLIGATOR_KEY_LEN 64
#define TAG_LEN           16  // Set to 0 if your unencrypted capture omits the AEAD tag
#define TERMINATOR_LEN    16
#define MIN_HANDSHAKE_LEN (ELLIGATOR_KEY_LEN + TERMINATOR_LEN)
#define LENGTH_LEN        3
#define HEADER_LEN        1

// IDs that will be filled in by proto_register_bitcoinv2
static int proto_bitcoinv2 = -1;
static int hf_ellswift_key = -1;
static int hf_garbage = -1;
static int hf_terminator = -1;
static int hf_length = -1;
static int hf_header = -1;
static int hf_bitcoin_message = -1;
static int hf_tag = -1;
static int ett_bitcoinv2 = -1;
static int ett_bitcoinv2_bitcoin_message = -1;

// Will be set by proto_register_bitcoinv2
static dissector_handle_t bitcoinv2_handle;

// Will be set by proto_reg_handoff_bitcoinv2
static dissector_handle_t bitcoinv1_handle;

// Per-direction handshake buffer
typedef struct {
    bool has_base_seq;
    bool gave_up;
    uint32_t base_seq;
    uint32_t max_written;
    int version_off;       // -1 until version_ident is found
    uint32_t match_frame;  // frame number that completed version_ident
    uint8_t buf[VERSION_IDENT_SEARCH_LIMIT];

    // Used only if version_ident straddles two segments AND version spills past match_frame
    uint8_t *version_buf;
    uint32_t version_pdu_len;
    uint32_t version_written;
    uint32_t version_done_frame;
    uint32_t version_tail_in_done_frame;
} dir_state_t;

typedef struct {
    address init_addr;
    uint32_t init_port;
    dir_state_t dir[2];
} bitcoinv2_conv_t;

// Standard BIP-324 1-byte short message type IDs (index 0 unused)
static const char *bip324_short_id_to_cmd(uint8_t id) {
    static const char *const table[] = {NULL,          "addr",         "block",       "blocktxn",   "cmpctblock",
                                        "feefilter",   "filteradd",    "filterclear", "filterload", "getblocks",
                                        "getblocktxn", "getdata",      "getheaders",  "headers",    "inv",
                                        "mempool",     "merkleblock",  "notfound",    "ping",       "pong",
                                        "sendcmpct",   "tx",           "getcfilters", "cfilter",    "getcfheaders",
                                        "cfheaders",   "getcfcheckpt", "cfcheckpt",   "addrv2"};
    if (id < array_length(table)) return table[id];
    return NULL;
}

static uint32_t read_le24(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

static bitcoinv2_conv_t *new_bitcoinv2_conv_t(address *src, uint32_t srcport) {
    bitcoinv2_conv_t *st = wmem_new0(wmem_file_scope(), bitcoinv2_conv_t);
    st->dir[0].version_off = -1;
    st->dir[1].version_off = -1;

    copy_address_wmem(wmem_file_scope(), &st->init_addr, src);
    st->init_port = srcport;

    return st;
}

static bitcoinv2_conv_t *get_conv_state(packet_info *pinfo) {
    conversation_t *conv = find_or_create_conversation(pinfo);

    bitcoinv2_conv_t *st = (bitcoinv2_conv_t *)conversation_get_proto_data(conv, proto_bitcoinv2);
    if (!st) {
        st = new_bitcoinv2_conv_t(&pinfo->src, pinfo->srcport);
        conversation_add_proto_data(conv, proto_bitcoinv2, st);
    }
    return st;
}

static dir_state_t *get_dir_state(bitcoinv2_conv_t *st, packet_info *pinfo) {
    int idx = (addresses_equal(&st->init_addr, &pinfo->src) && st->init_port == pinfo->srcport) ? 0 : 1;
    return &st->dir[idx];
}

static int find_version_ident_buf(const uint8_t *buf, size_t len) {
    if (len < VERSION_IDENT_LEN) return -1;
    const uint8_t *hit = (const uint8_t *)ws_memmem(buf, len, version_ident, VERSION_IDENT_LEN);
    return hit ? (int)(hit - buf) : -1;
}

static void buffer_and_scan(dir_state_t *state, tvbuff_t *tvb, packet_info *pinfo, const struct tcpinfo *tcpinfo) {
    if (PINFO_FD_VISITED(pinfo) || state->version_off >= 0 || state->gave_up) return;

    uint32_t len = tvb_captured_length(tvb);
    if (len == 0) return;

    if (!state->has_base_seq) {
        state->base_seq = tcpinfo->seq;
        state->has_base_seq = true;
    }

    int32_t srel = (int32_t)(tcpinfo->seq - state->base_seq);
    if (srel < 0) return;

    uint32_t rel = (uint32_t)srel;
    if (rel >= (uint32_t)VERSION_IDENT_SEARCH_LIMIT) {
        state->gave_up = true;
        return;
    }

    uint32_t prev_max = state->max_written;
    uint32_t room = (uint32_t)VERSION_IDENT_SEARCH_LIMIT - rel;
    uint32_t to_copy = len < room ? len : room;
    if (rel + to_copy <= prev_max) return;

    tvb_memcpy(tvb, state->buf + rel, 0, to_copy);
    state->max_written = rel + to_copy;

    // Start at MIN_HANDSHAKE_LEN, scanning only newly added bytes + boundary overlap
    if (state->max_written >= MIN_HANDSHAKE_LEN + VERSION_IDENT_LEN) {
        size_t scan_start = MIN_HANDSHAKE_LEN;
        if (prev_max > MIN_HANDSHAKE_LEN + (VERSION_IDENT_LEN - 1)) {
            scan_start = prev_max - (VERSION_IDENT_LEN - 1);
        }

        int off = find_version_ident_buf(state->buf + scan_start, state->max_written - scan_start);
        if (off >= 0) {
            state->version_off = (int)scan_start + off;
            state->match_frame = pinfo->num;
            return;
        }
    }

    if (state->max_written >= (uint32_t)VERSION_IDENT_SEARCH_LIMIT) state->gave_up = true;
}

// Callback 1 for tcp_dissect_pdus: compute total wire length of one Bitcoin v2 message
static unsigned get_bitcoinv2_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data) {
    (void)pinfo;
    (void)data;
    uint32_t payload_len = tvb_get_letoh24(tvb, offset);
    return (unsigned)(LENGTH_LEN + HEADER_LEN + payload_len + TAG_LEN);
}

// Rewrite field_info entries created against v1_tvb so they point directly
// into the original TCP data source instead of a separate tab.
static void rebase_v1_tree(proto_node *node, tvbuff_t *v1_tvb, tvbuff_t *real_ds, int real_body_start,
                           int real_fallback_start) {
    if (!node) return;

    field_info *fi = PNODE_FINFO(node);
    if (fi && fi->ds_tvb == v1_tvb) {
        int start = fi->start;
        int len = fi->length;
        int end = start + len;

        fi->ds_tvb = real_ds;

        if (start >= 24) {
            fi->start = real_body_start + (start - 24);
        } else if (end > 24) {
            fi->start = real_body_start;
            fi->length = end - 24;
        } else {
            fi->start = real_fallback_start;
            fi->length = 0;
            // Fix #1: never hide container nodes (e.g., 0-body messages like verack)
            if (len > 0 && !node->first_child) proto_item_set_hidden(node);
        }

        if (fi->appendix_length > 0) {
            int app_start = fi->appendix_start;
            if (app_start >= 24) {
                fi->appendix_start = real_body_start + (app_start - 24);
            } else {
                fi->appendix_start = real_fallback_start;
                fi->appendix_length = 0;
            }
        }
    }

    for (proto_node *child = node->first_child; child; child = child->next) {
        rebase_v1_tree(child, v1_tvb, real_ds, real_body_start, real_fallback_start);
    }
}

static int dissect_bitcoinv2_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    (void)data;

    proto_item *t_root = proto_tree_add_item(tree, proto_bitcoinv2, tvb, 0, -1, ENC_NA);
    proto_tree *t_msg = proto_item_add_subtree(t_root, ett_bitcoinv2_bitcoin_message);

    unsigned int payload_len = 0;
    proto_tree_add_item_ret_uint(t_msg, hf_length, tvb, 0, LENGTH_LEN, ENC_LITTLE_ENDIAN, &payload_len);

    uint8_t header = tvb_get_uint8(tvb, LENGTH_LEN);
    proto_tree_add_item(t_msg, hf_header, tvb, LENGTH_LEN, HEADER_LEN, ENC_NA);

    int payload_off = LENGTH_LEN + HEADER_LEN;

    // BIP-324 header bit 7 is the ignore/decoy flag — do not parse as a Bitcoin message
    if (header & 0x80) {
        if (payload_len > 0) proto_tree_add_item(t_msg, hf_bitcoin_message, tvb, payload_off, (int)payload_len, ENC_NA);
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Decoy");
    } else if (payload_len >= 1) {
        uint8_t msg_type = tvb_get_uint8(tvb, payload_off);
        char cmd[12] = {0};
        uint32_t type_len = 0;
        bool valid_cmd = false;

        if (msg_type == 0x00) {
            if (payload_len >= 13) {
                tvb_memcpy(tvb, cmd, payload_off + 1, 12);
                type_len = 13;
                valid_cmd = true;
            }
        } else {
            const char *name = bip324_short_id_to_cmd(msg_type);
            type_len = 1;
            if (name) {
                size_t name_len = strlen(name);
                memcpy(cmd, name, MIN(name_len, sizeof(cmd)));
                valid_cmd = true;
            }
        }

        if (valid_cmd && bitcoinv1_handle) {
            uint32_t body_len = payload_len - type_len;
            int body_off = payload_off + (int)type_len;
            int rem = (int)tvb_captured_length_remaining(tvb, body_off);
            uint32_t avail_body = rem > 0 ? ((uint32_t)rem < body_len ? (uint32_t)rem : body_len) : 0;

            uint8_t *v1_buf = (uint8_t *)wmem_alloc0(pinfo->pool, 24 + avail_body);

            // 4B mainnet magic (0xf9beb4d9)
            v1_buf[0] = 0xf9;
            v1_buf[1] = 0xbe;
            v1_buf[2] = 0xb4;
            v1_buf[3] = 0xd9;
            // 12B zero-padded ASCII command
            memcpy(v1_buf + 4, cmd, 12);
            // 4B little-endian payload length (full reported body length)
            v1_buf[16] = (uint8_t)(body_len & 0xff);
            v1_buf[17] = (uint8_t)((body_len >> 8) & 0xff);
            v1_buf[18] = (uint8_t)((body_len >> 16) & 0xff);
            v1_buf[19] = (uint8_t)((body_len >> 24) & 0xff);
            // v1_buf[20..23] stays 0x00000000 (placeholder checksum)

            if (avail_body > 0) tvb_memcpy(tvb, v1_buf + 24, body_off, avail_body);

            tvbuff_t *v1_tvb = tvb_new_child_real_data(tvb, v1_buf, 24 + avail_body, (int)(24 + body_len));

            tvbuff_t *real_ds = tvb_get_ds_tvb(tvb);
            int real_fallback_start = (int)tvb_raw_offset(tvb) + payload_off;
            int real_body_start = real_fallback_start + (int)type_len;

            proto_node *prev_last = t_msg ? t_msg->last_child : NULL;

            col_set_writable(pinfo->cinfo, COL_PROTOCOL, false);
            TRY { call_dissector(bitcoinv1_handle, v1_tvb, pinfo, t_msg); }
            FINALLY {
                col_set_writable(pinfo->cinfo, COL_PROTOCOL, true);
                col_set_fence(pinfo->cinfo, COL_INFO);
                if (t_msg) {
                    proto_node *first_new = prev_last ? prev_last->next : t_msg->first_child;
                    for (proto_node *n = first_new; n; n = n->next) {
                        rebase_v1_tree(n, v1_tvb, real_ds, real_body_start, real_fallback_start);
                    }
                }
            }
            ENDTRY;
        } else {
            proto_tree_add_item(t_msg, hf_bitcoin_message, tvb, payload_off, (int)payload_len, ENC_NA);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Unknown type 0x%02x", msg_type);
        }
    } else {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Empty");
    }

    // Lock in this PDU's Info text before tcp_dissect_pdus() loops to the next message
    col_set_fence(pinfo->cinfo, COL_INFO);

#if TAG_LEN > 0
    proto_tree_add_item(t_msg, hf_tag, tvb, payload_off + (int)payload_len, TAG_LEN, ENC_NA);
#endif

    return (int)tvb_captured_length(tvb);
}

// Dissect only the handshake portion [0 .. vident_offset - 1]
static void dissect_handshake(tvbuff_t *tvb, proto_tree *tree, int vident_offset) {
    int terminator_offset = vident_offset - TERMINATOR_LEN;
    int garbage_offset = ELLIGATOR_KEY_LEN;
    int garbage_len = terminator_offset - garbage_offset;

    proto_item *t_root = proto_tree_add_item(tree, proto_bitcoinv2, tvb, 0, -1, ENC_NA);
    proto_tree *t_bitcoinv2 = proto_item_add_subtree(t_root, ett_bitcoinv2);

    proto_tree_add_item(t_bitcoinv2, hf_ellswift_key, tvb, 0, ELLIGATOR_KEY_LEN, ENC_NA);
    if (garbage_len > 0) proto_tree_add_item(t_bitcoinv2, hf_garbage, tvb, garbage_offset, garbage_len, ENC_NA);
    proto_tree_add_item(t_bitcoinv2, hf_terminator, tvb, terminator_offset, TERMINATOR_LEN, ENC_NA);
}

// Helper to add whichever portion of a handshake field overlaps the current TCP segment
static void add_handshake_slice(proto_tree *tree, int hf, tvbuff_t *tvb, uint32_t seg_start, uint32_t seg_end,
                                uint32_t field_start, uint32_t field_end) {
    uint32_t lo = seg_start > field_start ? seg_start : field_start;
    uint32_t hi = seg_end < field_end ? seg_end : field_end;
    if (lo < hi) proto_tree_add_item(tree, hf, tvb, (int)(lo - seg_start), (int)(hi - lo), ENC_NA);
}

static int dissect_bitcoinv2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    uint32_t len = tvb_captured_length(tvb);
    if (!data || len == 0) return 0;

    const struct tcpinfo *tcpinfo = (const struct tcpinfo *)data;
    bitcoinv2_conv_t *st = get_conv_state(pinfo);
    dir_state_t *d = get_dir_state(st, pinfo);

    // Keep buffering the opposite direction on Pass 1 after the conversation is claimed
    buffer_and_scan(d, tvb, pinfo, tcpinfo);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bitcoin v2");
    // Only clears text after any existing fence (wipes TCP info on call 1,
    // preserves our earlier PDU info if TCP calls us twice on the same frame).
    col_clear(pinfo->cinfo, COL_INFO);

    if (d->version_off >= 0 && pinfo->num == d->match_frame) {
        uint32_t seg_start = tcpinfo->seq - d->base_seq;

        tvbuff_t *hs_tvb = NULL;
        if (seg_start == 0) {
            hs_tvb = tvb_new_subset_length(tvb, 0, d->version_off);
        } else {
            hs_tvb = tvb_new_child_real_data(tvb, d->buf, (unsigned)d->version_off, d->version_off);
            add_new_data_source(pinfo, hs_tvb, "Reassembled Bitcoin v2 Handshake");
        }
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Handshake");
        col_set_fence(pinfo->cinfo, COL_INFO);
        dissect_handshake(hs_tvb, tree, d->version_off);

        if (seg_start <= (uint32_t)d->version_off) {
            int seg_vident_off = (int)((uint32_t)d->version_off - seg_start);
            if (seg_vident_off < (int)len) {
                tvbuff_t *pdu_tvb = tvb_new_subset_remaining(tvb, seg_vident_off);
                tcp_dissect_pdus(pdu_tvb, pinfo, tree, true, LENGTH_LEN, get_bitcoinv2_pdu_len, dissect_bitcoinv2_pdu,
                                 data);
                if (pinfo->desegment_len != 0) pinfo->desegment_offset += seg_vident_off;
            }
        } else {
            uint32_t prefix_len = seg_start - (uint32_t)d->version_off;
            uint32_t ver_pdu_len = (uint32_t)(LENGTH_LEN + HEADER_LEN + read_le24(d->buf + d->version_off) + TAG_LEN);

            if (prefix_len + len >= ver_pdu_len) {
                uint32_t from_tvb = ver_pdu_len - prefix_len;
                uint8_t *ver_raw = (uint8_t *)wmem_alloc(pinfo->pool, ver_pdu_len);
                memcpy(ver_raw, d->buf + d->version_off, prefix_len);
                if (from_tvb > 0) tvb_memcpy(tvb, ver_raw + prefix_len, 0, from_tvb);

                tvbuff_t *ver_tvb = tvb_new_child_real_data(tvb, ver_raw, ver_pdu_len, (int)ver_pdu_len);
                add_new_data_source(pinfo, ver_tvb, "Reassembled Bitcoin v2 Version");
                dissect_bitcoinv2_pdu(ver_tvb, pinfo, tree, data);

                if (from_tvb < len) {
                    tvbuff_t *rest_tvb = tvb_new_subset_remaining(tvb, (int)from_tvb);
                    tcp_dissect_pdus(rest_tvb, pinfo, tree, true, LENGTH_LEN, get_bitcoinv2_pdu_len,
                                     dissect_bitcoinv2_pdu, data);
                    if (pinfo->desegment_len != 0) pinfo->desegment_offset += (int)from_tvb;
                }
            } else {
                if (!PINFO_FD_VISITED(pinfo) && !d->version_buf) {
                    d->version_pdu_len = ver_pdu_len;
                    d->version_buf = (uint8_t *)wmem_alloc(wmem_file_scope(), ver_pdu_len);
                    memcpy(d->version_buf, d->buf + d->version_off, prefix_len);
                    tvb_memcpy(tvb, d->version_buf + prefix_len, 0, len);
                    d->version_written = prefix_len + len;
                }
                col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Version fragment");
                col_set_fence(pinfo->cinfo, COL_INFO);
            }
        }
    } else if (d->version_off >= 0 && pinfo->num < d->match_frame && d->has_base_seq) {
        uint32_t seg_start = tcpinfo->seq - d->base_seq;
        uint32_t seg_end = seg_start + len;
        uint32_t term_off = (uint32_t)(d->version_off - TERMINATOR_LEN);

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Handshake fragment (stream bytes %u..%u)", seg_start,
                            seg_end - 1);
        col_set_fence(pinfo->cinfo, COL_INFO);

        proto_item *t_root = proto_tree_add_item(tree, proto_bitcoinv2, tvb, 0, -1, ENC_NA);
        proto_tree *t_bitcoinv2 = proto_item_add_subtree(t_root, ett_bitcoinv2);

        add_handshake_slice(t_bitcoinv2, hf_ellswift_key, tvb, seg_start, seg_end, 0, ELLIGATOR_KEY_LEN);
        add_handshake_slice(t_bitcoinv2, hf_garbage, tvb, seg_start, seg_end, ELLIGATOR_KEY_LEN, term_off);
        add_handshake_slice(t_bitcoinv2, hf_terminator, tvb, seg_start, seg_end, term_off, (uint32_t)d->version_off);
    } else if (d->version_off >= 0 && pinfo->num > d->match_frame) {
        if (d->version_buf) {
            if (!PINFO_FD_VISITED(pinfo) && d->version_done_frame == 0) {
                int32_t srel = (int32_t)(tcpinfo->seq - d->base_seq);
                if (srel >= d->version_off) {
                    uint32_t rel_ver = (uint32_t)(srel - d->version_off);
                    if (rel_ver < d->version_pdu_len) {
                        uint32_t need = d->version_pdu_len - rel_ver;
                        uint32_t take = len < need ? len : need;
                        tvb_memcpy(tvb, d->version_buf + rel_ver, 0, take);
                        if (rel_ver + take > d->version_written) d->version_written = rel_ver + take;
                        if (d->version_written >= d->version_pdu_len) {
                            d->version_done_frame = pinfo->num;
                            d->version_tail_in_done_frame = take;
                        }
                    }
                }
            }

            if (d->version_done_frame == 0 || pinfo->num < d->version_done_frame) {
                col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Version fragment");
                col_set_fence(pinfo->cinfo, COL_INFO);
                proto_tree_add_item(tree, proto_bitcoinv2, tvb, 0, -1, ENC_NA);
                return (int)len;
            }

            if (pinfo->num == d->version_done_frame) {
                tvbuff_t *ver_tvb =
                    tvb_new_child_real_data(tvb, d->version_buf, d->version_pdu_len, (int)d->version_pdu_len);
                add_new_data_source(pinfo, ver_tvb, "Reassembled Bitcoin v2 Version");
                dissect_bitcoinv2_pdu(ver_tvb, pinfo, tree, data);

                if (d->version_tail_in_done_frame < len) {
                    tvbuff_t *rest_tvb = tvb_new_subset_remaining(tvb, (int)d->version_tail_in_done_frame);
                    tcp_dissect_pdus(rest_tvb, pinfo, tree, true, LENGTH_LEN, get_bitcoinv2_pdu_len,
                                     dissect_bitcoinv2_pdu, data);
                    if (pinfo->desegment_len != 0) pinfo->desegment_offset += (int)d->version_tail_in_done_frame;
                }
                return (int)len;
            }
        }

        tcp_dissect_pdus(tvb, pinfo, tree, true, LENGTH_LEN, get_bitcoinv2_pdu_len, dissect_bitcoinv2_pdu, data);
    } else {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Handshake (pending)");
        col_set_fence(pinfo->cinfo, COL_INFO);
        proto_tree_add_item(tree, proto_bitcoinv2, tvb, 0, -1, ENC_NA);
    }

    return (int)len;
}

/* Heuristic wrapper. The return type of heur_dissector_t differs between
 * Wireshark releases (gboolean in 4.2, bool in 4.4+), so select it by version. */
#if (WIRESHARK_VERSION_MAJOR > 4) || \
    (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR >= 3)
typedef bool heur_result_t;
#else
typedef gboolean heur_result_t;
#endif

static heur_result_t dissect_bitcoinv2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    if (!data || tvb_captured_length(tvb) == 0) return false;

    const struct tcpinfo *tcpinfo = (const struct tcpinfo *)data;
    bitcoinv2_conv_t *st = get_conv_state(pinfo);
    dir_state_t *d = get_dir_state(st, pinfo);

    buffer_and_scan(d, tvb, pinfo, tcpinfo);
    if (d->version_off < 0) return false;

    // Bind the entire conversation so Pass 2 retroactively dissects earlier packets
    // and future packets bypass the heuristic.
    conversation_t *conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, bitcoinv2_handle);
    dissect_bitcoinv2(tvb, pinfo, tree, data);
    return true;
}

static void proto_register_bitcoinv2(void) {
    static hf_register_info hf[] = {
        {&hf_ellswift_key,
         {"Elligator Swift Key", "bitcoinv2.ellswift_key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_garbage, {"Garbage", "bitcoinv2.garbage", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_terminator, {"Garbage Terminator", "bitcoinv2.terminator", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_length, {"Length", "bitcoinv2.length", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_header, {"Header", "bitcoinv2.header", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_bitcoin_message, {"Payload", "bitcoinv2.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_tag, {"AEAD Tag", "bitcoinv2.tag", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };
    static int *ett[] = {&ett_bitcoinv2, &ett_bitcoinv2_bitcoin_message};

    proto_bitcoinv2 = proto_register_protocol("Bitcoin v2", "bitcoinv2", "bitcoinv2");
    proto_register_field_array(proto_bitcoinv2, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bitcoinv2_handle = register_dissector("bitcoinv2", dissect_bitcoinv2, proto_bitcoinv2);
}

static void proto_reg_handoff_bitcoinv2(void) {
    bitcoinv1_handle = find_dissector("bitcoin");

    heur_dissector_add("tcp", dissect_bitcoinv2_heur, "Bitcoin v2 over TCP", "bitcoinv2_tcp", proto_bitcoinv2,
                       HEURISTIC_ENABLE);
}

WS_DLL_PUBLIC void plugin_register(void) {
    static proto_plugin plug;
    plug.register_protoinfo = proto_register_bitcoinv2;
    plug.register_handoff = proto_reg_handoff_bitcoinv2;
    proto_register_plugin(&plug);
}

#ifdef WS_PLUGIN_DESC_DISSECTOR
WS_DLL_PUBLIC uint32_t plugin_describe(void) { return WS_PLUGIN_DESC_DISSECTOR; }
#endif
