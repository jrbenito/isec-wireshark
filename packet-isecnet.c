/*
 *
 */

#include "config.h"

#include <glib.h>

#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/dwarf.h>
#include <epan/dissectors/packet-tcp.h>

#define ISEC_PORT 9009

static dissector_handle_t isecnet_handle;

/* Protocol ISECnet (isn) */
static int proto_isecnet = -1;

static int hf_isn_length = -1;
#define ISN_LEN_SZ 1
static int hf_isn_cmd = -1;
#define ISN_CMD_SZ 1
static int hf_isn_payload = -1;
static int hf_isn_chksum = -1;
#define ISN_CHKS_SZ 1

#define ISN_HDR_SZ (ISN_CHKS_SZ + ISN_LEN_SZ) /* header + footer size */

static gint ett_isn = -1;

/* Reassemble SMPP TCP segments */
static gboolean reassemble_isecnet_over_tcp = TRUE;
/* Module Preferences */
static gboolean isecnet_summary_in_tree = TRUE;

static guint get_isecnet_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint msg_len = 0;

	msg_len = (guint)tvb_get_guint8(tvb,offset) + ISN_HDR_SZ;

	/* ISECnet has short frames for Ack, for instance 0xFE ack
	 * and F7 heartbeat
	 *
         * ToDo: Evaluate if it worthwhile handle any len>203 as short 
         *       frame.
         *       Will handle only two well documented short frames for
         *       now
         */
	if ((msg_len == 0xFE) || (msg_len == 0xF7)) {
		/* short frames have only header */
		msg_len = ISN_LEN_SZ; 
	} 
	else {  /* Normal (long) frame length is payload length (first 
		 *  field) + header and footer size
		 */
		msg_len = (guint)tvb_get_guint8(tvb,offset) + ISN_HDR_SZ;
	}

	return msg_len;
}

/* Dissect the ISECnet frame */
static int dissect_isecnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti = NULL;

	gint offset = 0;
	guint8 isn_pl_length = tvb_get_guint8(tvb, 0)-1;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISECnet");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	if (tree) { /* we are being asked for details */

		ti = proto_tree_add_item(tree, proto_isecnet, tvb, 0, -1, ENC_NA);

	}

	return tvb_captured_length(tvb);
}

/**
 * The minimum size of a ISECnet packet is 3 bytes (Length, CMD and checksum),
 * and the maximum size is 203 bytes (per documents and 256 due length filed
 * limitation). Hence minimum fixed lentgh should be 2 bytes for tcp_dissect_pdu.
 *
 * Since header field Length is only one byte long, it will be present within a
 * single TCP segment and no issue will be raised by calling tcp_dissect_pdu with
 * minimum length set to 2 (we need only the first byte of isecnet_pdu).
 *
 * ToDo: Ivestigate if a minimum length of 1 would be enougth to determine full
 *      length (one byte) of a ISECnet frame. Need to better understand the
 *      reassemble process.
**/
static int dissect_isecnet_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	tcp_dissect_pdus(tvb, pinfo, tree,
			reassemble_isecnet_over_tcp, 
			2,			    /* Length can be determined within 1st byte */
			get_isecnet_pdu_len, 
			dissect_isecnet, data);

	return tvb_captured_length(tvb);
}

/*
 * Register the protocol with Wireshark
 */
void proto_register_isecnet(void)
{
	/* List of header fields */
	static hf_register_info hf_isn[] = {
		{ &hf_isn_length,
		    { "Length", "ISECnet.length",
		      FT_UINT8, BASE_DEC, NULL, 0X0,
		      NULL, HFILL }},
		{ &hf_isn_cmd,
		    { "Command", "ISECnet.cmd",
		      FT_UINT8, BASE_HEX, NULL, 0x0,
		      NULL, HFILL }},
		{ &hf_isn_payload,
		    { "Payload", "ISECnet.payload",
		      FT_NONE, BASE_NONE, NULL, 0x0,
		      NULL, HFILL}},
		{ &hf_isn_chksum,
		    { "Checksum", "ISECnet.chksum",
		      FT_UINT8, BASE_HEX, NULL,	0x0,
		      NULL, HFILL}}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_isn
	};

	module_t *isecnet_module;

	proto_isecnet = proto_register_protocol (
		"Intelbras Security Protocol", /* name       */
		"ISECnet",          /* short name */
		"isecnet"           /* abbrev     */
	);

	isecnet_handle = new_register_dissector("isecnet", dissect_isecnet_data, proto_isecnet);

	proto_register_field_array(proto_isecnet, hf_isn, array_length(hf_isn));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register configuration preferences */
	isecnet_module = prefs_register_protocol(proto_isecnet, NULL);
	prefs_register_bool_preference(isecnet_module, "summary_in_tree",
			"Show TCP summary in protocol tree",
			"Whether the TCP summary line should be shown in the protocol tree",
			&isecnet_summary_in_tree);

}

/*
 * Dissector Handoff
 */
void proto_reg_handoff_isecnet(void)
{
	dissector_add_handle("tcp.port", isecnet_handle);
}
/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
