#define WS_BUILD_DLL
#define WS_LOG_DOMAIN "bitcoinv2"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// Contains WS_VERSION and WS_VERSION_NUM
#include <ws_version.h>

#ifndef WS_VERSION_NUM
#define WS_VERSION_NUM(maj, min, mic) (((maj) * 10000) + ((min) * 100) + (mic))
#endif
#ifndef WS_VERSION
#define WS_VERSION WS_VERSION_NUM(WIRESHARK_VERSION_MAJOR, WIRESHARK_VERSION_MINOR, WIRESHARK_VERSION_MICRO)
#endif

// Top-level header: wireshark.h arrived in 3.7/4.0
#if WS_VERSION >= WS_VERSION_NUM(4, 0, 0)
#include <wireshark.h>
#else
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <glib.h>
#include <ws_attributes.h>
#include <ws_symbol_export.h>
#endif

#include <epan/dissectors/packet-tcp.h>
#include <epan/exceptions.h>

#ifdef __has_include
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

// Wireshark 4.4 removed the GLib "g" prefix from tvb_get_guintX / tvb_get_gintX
#if WS_VERSION < WS_VERSION_NUM(4, 4, 0)
#define tvb_get_uint8 tvb_get_guint8
#endif

// heur_dissector_t switched from gboolean to bool in Wireshark 4.3/4.4
#if WS_VERSION >= WS_VERSION_NUM(4, 3, 0)
typedef bool heur_result_t;
#else
typedef gboolean heur_result_t;
#endif

#if WIRESHARK_VERSION_MAJOR < 4
static const uint8_t *ws_memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }
    const uint8_t *h = (const uint8_t *)haystack;
    const uint8_t *n = (const uint8_t *)needle;
    size_t remaining = haystack_len - needle_len + 1;
    while (remaining > 0) {
        const uint8_t *p = (const uint8_t *)memchr(h, n[0], remaining);
        if (!p) {
            return NULL;
        }
        if (memcmp(p, n, needle_len) == 0) {
            return p;
        }
        remaining -= (size_t)(p - h) + 1;
        h = p + 1;
    }
    return NULL;
}
#endif

/*
 * Use WS_DLL_PUBLIC_DEF for exported definitions and WS_DLL_PUBLIC for declarations.
 */

// PROJECT_VERSION is provided by cmake
WS_DLL_PUBLIC_DEF const char plugin_version[] = PROJECT_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
#ifdef WS_PLUGIN_DESC_DISSECTOR
WS_DLL_PUBLIC uint32_t plugin_describe(void);
#endif

// Bytes that identify the version message in v2:
// Three bytes little-endian length, one byte BIP-324 header, one byte compression indicator
static const uint8_t version_ident[] = {0x73, 0x00, 0x00, 0x00, 0x00, 'v',  'e',  'r', 's',
                                        'i',  'o',  'n',  0x00, 0x00, 0x00, 0x00, 0x00};

#define VERSION_IDENT_LEN (sizeof(version_ident))
#define VERSION_IDENT_SEARCH_LIMIT 5000

#define ELLIGATOR_KEY_LEN 64
#define TAG_LEN 16  // Set to 0 if your unencrypted capture omits the AEAD tag
#define TERMINATOR_LEN 16
#define MIN_HANDSHAKE_LEN (ELLIGATOR_KEY_LEN + TERMINATOR_LEN)
#define LENGTH_LEN 3
#define HEADER_LEN 1
#define P2P_COMMAND_LENGTH 12

// IDs filled in by proto_register_bitcoinv2
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
static dissector_handle_t bitcoinv1_handle;

// 4B mainnet magic (0xf9beb4d9)
static const uint8_t bitcoinv1_magic[] = {0xf9, 0xbe, 0xb4, 0xd9};

static const int VERSION_BITCOINV1_COMMAND_PREFIX_LEN = 24;

static const uint8_t MASK_U8_BIT7 = 0x80;
static const uint8_t MASK_U8_ALL = 0xff;
static const uint8_t SHIFT_BYTE1_LE = 8;
static const uint8_t SHIFT_BYTE2_LE = 16;
static const uint8_t SHIFT_BYTE3_LE = 24;

// Per-direction handshake buffer
typedef struct {
    bool has_base_seq;
    bool gave_up;
    uint32_t base_seq;
    uint32_t max_written;
    int version_off;       // -1 until version_ident is found
    uint32_t match_frame;  // frame number that completed version_ident
    uint8_t buf[VERSION_IDENT_SEARCH_LIMIT];

    // Used only if version_ident straddles two segments
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
    return id < array_length(table) ? table[id] : NULL;
}

static uint32_t read_le24(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << SHIFT_BYTE1_LE) | ((uint32_t)p[2] << SHIFT_BYTE2_LE);
}

static void write_le32(uint8_t *p, uint32_t val) {
    p[0] = (uint8_t)(val & MASK_U8_ALL);
    p[1] = (uint8_t)((val >> SHIFT_BYTE1_LE) & MASK_U8_ALL);
    p[2] = (uint8_t)((val >> SHIFT_BYTE2_LE) & MASK_U8_ALL);
    p[3] = (uint8_t)((val >> SHIFT_BYTE3_LE) & MASK_U8_ALL);
}

static void append_info_fenced(packet_info *pinfo, const char *str) {
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", str);
    col_set_fence(pinfo->cinfo, COL_INFO);
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

static void buffer_and_scan(dir_state_t *state, tvbuff_t *tvb, packet_info *pinfo, const struct tcpinfo *tcpinfo) {
    if (PINFO_FD_VISITED(pinfo) || state->version_off >= 0 || state->gave_up) {
        return;
    }

    uint32_t len = tvb_captured_length(tvb);
    if (len == 0) {
        return;
    }

    if (!state->has_base_seq) {
        state->base_seq = tcpinfo->seq;
        state->has_base_seq = true;
    }

    int32_t srel = (int32_t)(tcpinfo->seq - state->base_seq);
    if (srel < 0) {
        return;
    }

    uint32_t rel = (uint32_t)srel;
    if (rel >= (uint32_t)VERSION_IDENT_SEARCH_LIMIT) {
        state->gave_up = true;
        return;
    }

    uint32_t prev_max = state->max_written;
    uint32_t room = (uint32_t)VERSION_IDENT_SEARCH_LIMIT - rel;
    uint32_t to_copy = MIN(len, room);
    if (rel + to_copy <= prev_max) {
        return;
    }

    tvb_memcpy(tvb, state->buf + rel, 0, to_copy);
    state->max_written = rel + to_copy;

    // Start at MIN_HANDSHAKE_LEN, scanning only newly added bytes + boundary overlap
    if (state->max_written >= MIN_HANDSHAKE_LEN + VERSION_IDENT_LEN) {
        size_t scan_start = MIN_HANDSHAKE_LEN;
        if (prev_max > MIN_HANDSHAKE_LEN + (VERSION_IDENT_LEN - 1)) {
            scan_start = prev_max - (VERSION_IDENT_LEN - 1);
        }

        const uint8_t *hit =
            ws_memmem(state->buf + scan_start, state->max_written - scan_start, version_ident, VERSION_IDENT_LEN);
        if (hit) {
            state->version_off = (int)(hit - state->buf);
            state->match_frame = pinfo->num;
            return;
        }
    }

    if (state->max_written >= (uint32_t)VERSION_IDENT_SEARCH_LIMIT) {
        state->gave_up = true;
    }
}

// Callback 1 for tcp_dissect_pdus: compute total wire length of one Bitcoin v2 message
static unsigned get_bitcoinv2_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    uint32_t payload_len = tvb_get_letoh24(tvb, offset);
    return (unsigned)(LENGTH_LEN + HEADER_LEN + payload_len + TAG_LEN);
}

// Rewrite field_info entries created against v1_tvb so they point directly
// into the original TCP data source instead of a separate tab.
static void rebase_v1_tree(proto_node *node, tvbuff_t *v1_tvb, tvbuff_t *real_ds, int real_body_start,
                           int real_fallback_start) {
    if (!node) {
        return;
    }

    field_info *fi = PNODE_FINFO(node);
    if (fi && fi->ds_tvb == v1_tvb) {
        int start = fi->start;
        int len = fi->length;
        int end = start + len;

        fi->ds_tvb = real_ds;

        if (start >= VERSION_BITCOINV1_COMMAND_PREFIX_LEN) {
            fi->start = real_body_start + (start - VERSION_BITCOINV1_COMMAND_PREFIX_LEN);
        } else if (end > VERSION_BITCOINV1_COMMAND_PREFIX_LEN) {
            fi->start = real_body_start;
            fi->length = end - VERSION_BITCOINV1_COMMAND_PREFIX_LEN;
        } else {
            fi->start = real_fallback_start;
            fi->length = 0;
            // Never hide container nodes (e.g., 0-body messages like verack)
            if (len > 0 && !node->first_child) {
                proto_item_set_hidden(node);
            }
        }

        if (fi->appendix_length > 0) {
            int app_start = fi->appendix_start;
            if (app_start >= VERSION_BITCOINV1_COMMAND_PREFIX_LEN) {
                fi->appendix_start = real_body_start + (app_start - VERSION_BITCOINV1_COMMAND_PREFIX_LEN);
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

static void handle_v2_message_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *t_msg, const uint8_t *cmd,
                                      uint32_t payload_len, uint32_t type_len, int payload_off) {
    uint32_t body_len = payload_len - type_len;
    int body_off = payload_off + (int)type_len;
    int rem = tvb_captured_length_remaining(tvb, body_off);
    uint32_t avail_body = rem > 0 ? MIN((uint32_t)rem, body_len) : 0;

    // Synthesize a 24B Bitcoin v1 header: [4B magic][12B command][4B LE length][4B zero checksum]
    uint8_t *v1_buf = (uint8_t *)wmem_alloc0(pinfo->pool, (size_t)VERSION_BITCOINV1_COMMAND_PREFIX_LEN + avail_body);
    size_t off = 0;

    memcpy(v1_buf + off, bitcoinv1_magic, sizeof(bitcoinv1_magic));
    off += sizeof(bitcoinv1_magic);

    memcpy(v1_buf + off, cmd, P2P_COMMAND_LENGTH);
    off += P2P_COMMAND_LENGTH;

    write_le32(v1_buf + off, body_len);
    // Remaining 4 bytes stay 0x00000000 (placeholder checksum)

    if (avail_body > 0) {
        tvb_memcpy(tvb, v1_buf + VERSION_BITCOINV1_COMMAND_PREFIX_LEN, body_off, avail_body);
    }

    tvbuff_t *v1_tvb = tvb_new_child_real_data(tvb, v1_buf, (unsigned)VERSION_BITCOINV1_COMMAND_PREFIX_LEN + avail_body,
                                               VERSION_BITCOINV1_COMMAND_PREFIX_LEN + (int)body_len);

    tvbuff_t *real_ds = tvb_get_ds_tvb(tvb);
    int real_fallback_start = tvb_raw_offset(tvb) + payload_off;
    int real_body_start = real_fallback_start + (int)type_len;

    proto_node *prev_last = t_msg ? t_msg->last_child : NULL;

    col_set_writable(pinfo->cinfo, COL_PROTOCOL, false);
    TRY { call_dissector(bitcoinv1_handle, v1_tvb, pinfo, t_msg); }
    FINALLY {
        col_set_writable(pinfo->cinfo, COL_PROTOCOL, true);
        col_set_fence(pinfo->cinfo, COL_INFO);
        if (t_msg) {
            proto_node *first_new = prev_last ? prev_last->next : t_msg->first_child;
            for (proto_node *node = first_new; node; node = node->next) {
                rebase_v1_tree(node, v1_tvb, real_ds, real_body_start, real_fallback_start);
            }
        }
    }
    ENDTRY;
}

// Decode the BIP-324 message type prefix into cmd. Returns prefix length (1 or 13), or 0 if invalid.
static uint32_t parse_v2_command(tvbuff_t *tvb, int payload_off, uint8_t cmd[P2P_COMMAND_LENGTH],
                                 uint32_t payload_len) {
    uint8_t msg_type = tvb_get_uint8(tvb, payload_off);
    if (msg_type == 0x00) {
        if (payload_len <= P2P_COMMAND_LENGTH) {
            return 0;
        }
        tvb_memcpy(tvb, cmd, payload_off + 1, P2P_COMMAND_LENGTH);
        return P2P_COMMAND_LENGTH + 1;
    }

    const char *name = bip324_short_id_to_cmd(msg_type);
    if (!name) {
        return 0;
    }
    for (size_t i = 0; i < P2P_COMMAND_LENGTH && name[i] != '\0'; i++) {
        cmd[i] = (uint8_t)name[i];
    }
    return 1;
}

static int dissect_bitcoinv2_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item *t_root = proto_tree_add_item(tree, proto_bitcoinv2, tvb, 0, -1, ENC_NA);
    proto_tree *t_msg = proto_item_add_subtree(t_root, ett_bitcoinv2_bitcoin_message);

    uint32_t payload_len = 0;
    proto_tree_add_item_ret_uint(t_msg, hf_length, tvb, 0, LENGTH_LEN, ENC_LITTLE_ENDIAN, &payload_len);

    uint8_t header = tvb_get_uint8(tvb, LENGTH_LEN);
    proto_tree_add_item(t_msg, hf_header, tvb, LENGTH_LEN, HEADER_LEN, ENC_NA);

    int payload_off = LENGTH_LEN + HEADER_LEN;

    // BIP-324 header bit 7 is the ignore/decoy flag — do not parse as a Bitcoin message
    if (header & MASK_U8_BIT7) {
        if (payload_len > 0) {
            proto_tree_add_item(t_msg, hf_bitcoin_message, tvb, payload_off, (int)payload_len, ENC_NA);
        }
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Decoy");
    } else if (payload_len == 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Empty");
    } else {
        uint8_t msg_type = tvb_get_uint8(tvb, payload_off);
        uint8_t cmd[P2P_COMMAND_LENGTH] = {0};
        uint32_t type_len = parse_v2_command(tvb, payload_off, cmd, payload_len);

        if (type_len > 0 && bitcoinv1_handle) {
            handle_v2_message_payload(tvb, pinfo, t_msg, cmd, payload_len, type_len, payload_off);
        } else {
            proto_tree_add_item(t_msg, hf_bitcoin_message, tvb, payload_off, (int)payload_len, ENC_NA);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Unknown type 0x%02x", msg_type);
        }
    }

    // Lock in this PDU's Info text before tcp_dissect_pdus() loops to the next message
    col_set_fence(pinfo->cinfo, COL_INFO);

#if TAG_LEN > 0
    proto_tree_add_item(t_msg, hf_tag, tvb, payload_off + (int)payload_len, TAG_LEN, ENC_NA);
#endif

    return (int)tvb_captured_length(tvb);
}

static void dissect_pdus_from(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t offset) {
    if (offset >= tvb_captured_length(tvb)) {
        return;
    }

    tvbuff_t *pdu_tvb = offset == 0 ? tvb : tvb_new_subset_remaining(tvb, (int)offset);
    tcp_dissect_pdus(pdu_tvb, pinfo, tree, true, LENGTH_LEN, get_bitcoinv2_pdu_len, dissect_bitcoinv2_pdu, data);
    if (pinfo->desegment_len != 0) {
        pinfo->desegment_offset += (int)offset;
    }
}

// Dissect only the handshake portion [0 .. vident_offset - 1]
static void dissect_handshake(tvbuff_t *tvb, proto_tree *tree, int vident_offset) {
    int terminator_offset = vident_offset - TERMINATOR_LEN;
    int garbage_offset = ELLIGATOR_KEY_LEN;
    int garbage_len = terminator_offset - garbage_offset;

    proto_item *t_root = proto_tree_add_item(tree, proto_bitcoinv2, tvb, 0, -1, ENC_NA);
    proto_tree *t_bitcoinv2 = proto_item_add_subtree(t_root, ett_bitcoinv2);

    proto_tree_add_item(t_bitcoinv2, hf_ellswift_key, tvb, 0, ELLIGATOR_KEY_LEN, ENC_NA);
    if (garbage_len > 0) {
        proto_tree_add_item(t_bitcoinv2, hf_garbage, tvb, garbage_offset, garbage_len, ENC_NA);
    }
    proto_tree_add_item(t_bitcoinv2, hf_terminator, tvb, terminator_offset, TERMINATOR_LEN, ENC_NA);
}

static void init_version_reassembly(dir_state_t *state, uint32_t seg_start) {
    uint32_t prefix_len = seg_start - (uint32_t)state->version_off;
    uint32_t ver_pdu_len = (uint32_t)(LENGTH_LEN + HEADER_LEN + read_le24(state->buf + state->version_off) + TAG_LEN);

    state->version_pdu_len = ver_pdu_len;
    state->version_buf = (uint8_t *)wmem_alloc(wmem_file_scope(), ver_pdu_len);

    uint32_t to_copy = MIN(prefix_len, ver_pdu_len);
    memcpy(state->version_buf, state->buf + state->version_off, to_copy);
    state->version_written = to_copy;
}

static void feed_version_buf(tvbuff_t *tvb, packet_info *pinfo, uint32_t len, const struct tcpinfo *tcpinfo,
                             dir_state_t *state) {
    if (PINFO_FD_VISITED(pinfo) || state->version_done_frame != 0) {
        return;
    }

    int32_t srel = (int32_t)(tcpinfo->seq - state->base_seq);
    if (srel < state->version_off) {
        return;
    }

    uint32_t rel_ver = (uint32_t)(srel - state->version_off);
    if (rel_ver >= state->version_pdu_len) {
        return;
    }

    uint32_t take = MIN(len, state->version_pdu_len - rel_ver);
    tvb_memcpy(tvb, state->version_buf + rel_ver, 0, take);
    state->version_written = MAX(state->version_written, rel_ver + take);

    if (state->version_written >= state->version_pdu_len) {
        state->version_done_frame = pinfo->num;
        state->version_tail_in_done_frame = take;
    }
}

// Handles frames belonging to a straddling version PDU.
// Returns true if this frame was consumed, false if normal PDU dissection should run.
static bool dissect_reassembled_version(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data, uint32_t len,
                                        const struct tcpinfo *tcpinfo, dir_state_t *state) {
    if (!state->version_buf) {
        return false;
    }

    feed_version_buf(tvb, pinfo, len, tcpinfo, state);

    if (state->version_done_frame == 0 || pinfo->num < state->version_done_frame) {
        append_info_fenced(pinfo, "Version fragment");
        if (pinfo->num != state->match_frame) {
            proto_tree_add_item(tree, proto_bitcoinv2, tvb, 0, -1, ENC_NA);
        }
        return true;
    }

    if (pinfo->num != state->version_done_frame) {
        return false;
    }

    tvbuff_t *ver_tvb =
        tvb_new_child_real_data(tvb, state->version_buf, state->version_pdu_len, (int)state->version_pdu_len);
    add_new_data_source(pinfo, ver_tvb, "Reassembled Bitcoin v2 Version");
    dissect_bitcoinv2_pdu(ver_tvb, pinfo, tree, data);
    dissect_pdus_from(tvb, pinfo, tree, data, state->version_tail_in_done_frame);
    return true;
}

static void dissect_bitcoinv2_detected_matched_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data,
                                                     uint32_t len, const struct tcpinfo *tcpinfo, dir_state_t *state) {
    uint32_t seg_start = tcpinfo->seq - state->base_seq;

    tvbuff_t *hs_tvb = NULL;
    if (seg_start == 0) {
        hs_tvb = tvb_new_subset_length(tvb, 0, state->version_off);
    } else {
        hs_tvb = tvb_new_child_real_data(tvb, state->buf, (unsigned)state->version_off, state->version_off);
        add_new_data_source(pinfo, hs_tvb, "Reassembled Bitcoin v2 Handshake");
    }
    append_info_fenced(pinfo, "Handshake");
    dissect_handshake(hs_tvb, tree, state->version_off);

    if (seg_start <= (uint32_t)state->version_off) {
        dissect_pdus_from(tvb, pinfo, tree, data, (uint32_t)state->version_off - seg_start);
        return;
    }

    // version_ident straddled the previous segment into this one
    if (!PINFO_FD_VISITED(pinfo) && !state->version_buf) {
        init_version_reassembly(state, seg_start);
    }
    dissect_reassembled_version(tvb, pinfo, tree, data, len, tcpinfo, state);
}

static void dissect_bitcoinv2_detected_before_matched(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t len,
                                                      const struct tcpinfo *tcpinfo, dir_state_t *state) {
    uint32_t seg_start = tcpinfo->seq - state->base_seq;
    uint32_t seg_end = seg_start + len;
    uint32_t term_off = (uint32_t)(state->version_off - TERMINATOR_LEN);

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Handshake fragment (stream bytes %u..%u)", seg_start,
                        seg_end - 1);
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_item *t_root = proto_tree_add_item(tree, proto_bitcoinv2, tvb, 0, -1, ENC_NA);
    proto_tree *t_bitcoinv2 = proto_item_add_subtree(t_root, ett_bitcoinv2);

    const struct {
        int hf;
        uint32_t field_start;
        uint32_t field_end;
    } slices[] = {
        {hf_ellswift_key, 0, ELLIGATOR_KEY_LEN},
        {hf_garbage, ELLIGATOR_KEY_LEN, term_off},
        {hf_terminator, term_off, (uint32_t)state->version_off},
    };

    for (size_t i = 0; i < array_length(slices); i++) {
        uint32_t lo = MAX(seg_start, slices[i].field_start);
        uint32_t hi = MIN(seg_end, slices[i].field_end);
        if (lo < hi) {
            proto_tree_add_item(t_bitcoinv2, slices[i].hf, tvb, (int)(lo - seg_start), (int)(hi - lo), ENC_NA);
        }
    }
}

static int dissect_bitcoinv2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    uint32_t len = tvb_captured_length(tvb);
    if (!data || len == 0) {
        return 0;
    }

    const struct tcpinfo *tcpinfo = (const struct tcpinfo *)data;
    bitcoinv2_conv_t *conv_state = get_conv_state(pinfo);
    dir_state_t *state = get_dir_state(conv_state, pinfo);

    // Keep buffering the opposite direction on Pass 1 after the conversation is claimed
    buffer_and_scan(state, tvb, pinfo, tcpinfo);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bitcoin v2");
    // Only clears text after any existing fence (wipes TCP info on call 1,
    // preserves our earlier PDU info if TCP calls us twice on the same frame).
    col_clear(pinfo->cinfo, COL_INFO);

    if (state->version_off < 0) {
        append_info_fenced(pinfo, "Handshake (pending)");
        proto_tree_add_item(tree, proto_bitcoinv2, tvb, 0, -1, ENC_NA);
        return (int)len;
    }

    if (pinfo->num < state->match_frame) {
        if (state->has_base_seq) {
            dissect_bitcoinv2_detected_before_matched(tvb, pinfo, tree, len, tcpinfo, state);
        }
    } else if (pinfo->num == state->match_frame) {
        dissect_bitcoinv2_detected_matched_frame(tvb, pinfo, tree, data, len, tcpinfo, state);
    } else if (!dissect_reassembled_version(tvb, pinfo, tree, data, len, tcpinfo, state)) {
        dissect_pdus_from(tvb, pinfo, tree, data, 0);
    }

    return (int)len;
}

static heur_result_t dissect_bitcoinv2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    if (!data || tvb_captured_length(tvb) == 0) {
        return false;
    }

    const struct tcpinfo *tcpinfo = (const struct tcpinfo *)data;
    bitcoinv2_conv_t *conv_state = get_conv_state(pinfo);
    dir_state_t *state = get_dir_state(conv_state, pinfo);

    buffer_and_scan(state, tvb, pinfo, tcpinfo);
    if (state->version_off < 0) {
        return false;
    }

    // Bind the entire conversation so Pass 2 retroactively dissects earlier packets
    // and future packets bypass the heuristic.
    conversation_t *conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, bitcoinv2_handle);
    dissect_bitcoinv2(tvb, pinfo, tree, data);
    return true;
}

static void proto_register_bitcoinv2(void) {
    static hf_register_info hf_args[] = {
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
    proto_register_field_array(proto_bitcoinv2, hf_args, array_length(hf_args));
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
