/*
 *
 */

#include "config.h"

#include <epan/packet.h>

#define ISEC_PORT 9009

static dissector_handle_t isecnet_handle;

/* Protocol ISECnet (isn) */
static int proto_isecnet = -1;

static int hf_isn_length = -1;
static int hf_isn_cmd = -1;
static int hf_isn_payload = -1;
static int hf_isn_chksum = -1;

static gint ett_isn = -1;


static void dissect_isecnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	guint8 isn_pl_length = tvb_get_guint8(tvb, 0)-1;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISECnet");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		proto_tree *isn_tree = NULL;

		ti = proto_tree_add_item(tree, proto_isecnet, tvb, 0, -1, ENC_NA);
		isn_tree = proto_item_add_subtree(ti, ett_isn);

		proto_tree_add_item(isn_tree, hf_isn_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(isn_tree, hf_isn_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		proto_tree_add_item(isn_tree, hf_isn_payload, tvb, offset, isn_pl_length, ENC_BIG_ENDIAN);
		offset += isn_pl_length;
		proto_tree_add_item(isn_tree, hf_isn_chksum, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
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
	
	proto_isecnet = proto_register_protocol (
		"Intelbras Security Protocol", /* name       */
		"ISECnet",          /* short name */
		"isecnet"           /* abbrev     */
	);

	isecnet_handle = new_register_dissector("isecnet", dissect_isecnet, proto_isecnet);

	proto_register_field_array(proto_isecnet, hf_isn, array_length(hf_isn));
	proto_register_subtree_array(ett, array_length(ett));
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
