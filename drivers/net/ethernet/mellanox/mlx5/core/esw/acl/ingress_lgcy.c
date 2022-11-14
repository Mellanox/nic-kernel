// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2020 Mellanox Technologies Inc. All rights reserved. */

#include "mlx5_core.h"
#include "eswitch.h"
#include "helper.h"
#include "lgcy.h"

static void esw_acl_ingress_lgcy_rules_destroy(struct mlx5_vport *vport)
{
	if (vport->ingress.legacy.drop_rule) {
		mlx5_del_flow_rules(vport->ingress.legacy.drop_rule);
		vport->ingress.legacy.drop_rule = NULL;
	}
	esw_acl_ingress_allow_rule_destroy(vport);
}

static int esw_acl_ingress_lgcy_groups_create(struct mlx5_eswitch *esw,
					      struct mlx5_vport *vport)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_core_dev *dev = esw->dev;
	struct mlx5_flow_group *g;
	void *match_criteria;
	u32 *flow_group_in;
	int err;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	match_criteria = MLX5_ADDR_OF(create_flow_group_in, flow_group_in, match_criteria);

	MLX5_SET(create_flow_group_in, flow_group_in, match_criteria_enable,
		 MLX5_MATCH_OUTER_HEADERS);
	if (vport->info.vlan || vport->info.qos)
		MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.cvlan_tag);
	if (vport->info.spoofchk) {
		MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.smac_47_16);
		MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.smac_15_0);
	}
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 0);

	g = mlx5_create_flow_group(vport->ingress.acl, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(dev, "vport[%d] ingress create untagged spoofchk flow group, err(%d)\n",
			 vport->vport, err);
		goto allow_err;
	}
	vport->ingress.legacy.allow_grp = g;

	memset(flow_group_in, 0, inlen);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 1);

	g = mlx5_create_flow_group(vport->ingress.acl, flow_group_in);
	if (IS_ERR(g)) {
		err = PTR_ERR(g);
		esw_warn(dev, "vport[%d] ingress create drop flow group, err(%d)\n",
			 vport->vport, err);
		goto drop_err;
	}
	vport->ingress.legacy.drop_grp = g;
	kvfree(flow_group_in);
	return 0;

drop_err:
	if (!IS_ERR_OR_NULL(vport->ingress.legacy.allow_grp)) {
		mlx5_destroy_flow_group(vport->ingress.legacy.allow_grp);
		vport->ingress.legacy.allow_grp = NULL;
	}
allow_err:
	kvfree(flow_group_in);
	return err;
}

static void esw_acl_ingress_lgcy_groups_destroy(struct mlx5_vport *vport)
{
	if (vport->ingress.legacy.allow_grp) {
		mlx5_destroy_flow_group(vport->ingress.legacy.allow_grp);
		vport->ingress.legacy.allow_grp = NULL;
	}
	if (vport->ingress.legacy.drop_grp) {
		mlx5_destroy_flow_group(vport->ingress.legacy.drop_grp);
		vport->ingress.legacy.drop_grp = NULL;
	}
}

int esw_acl_ingress_lgcy_setup(struct mlx5_eswitch *esw,
			       struct mlx5_vport *vport)
{
	struct mlx5_flow_destination drop_ctr_dst = {};
	struct mlx5_flow_destination *dst = NULL;
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec = NULL;
	struct mlx5_fc *counter;
	/* The ingress acl table contains 2 groups
	 * 1)Allowed traffic according to tagging and spoofcheck settings
	 * 2)Drop all other traffic.
	 */
	int table_size = 2;
	int dest_num = 0;
	int err = 0;
	u8 *smac_v;

	esw_acl_ingress_lgcy_cleanup(esw, vport);
	if (!vport->info.vlan && !vport->info.qos && !vport->info.spoofchk)
		return 0;

	vport->ingress.acl = esw_acl_table_create(esw, vport,
						  MLX5_FLOW_NAMESPACE_ESW_INGRESS,
						  table_size);
	if (IS_ERR(vport->ingress.acl)) {
		err = PTR_ERR(vport->ingress.acl);
		vport->ingress.acl = NULL;
		return err;
	}

	err = esw_acl_ingress_lgcy_groups_create(esw, vport);
	if (err)
		goto out;

	esw_debug(esw->dev,
		  "vport[%d] configure ingress rules, vlan(%d) qos(%d)\n",
		  vport->vport, vport->info.vlan, vport->info.qos);

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out;
	}

	if (vport->info.vlan || vport->info.qos)
		MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
				 outer_headers.cvlan_tag);

	if (vport->info.spoofchk) {
		MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
				 outer_headers.smac_47_16);
		MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
				 outer_headers.smac_15_0);
		smac_v = MLX5_ADDR_OF(fte_match_param,
				      spec->match_value,
				      outer_headers.smac_47_16);
		ether_addr_copy(smac_v, vport->info.mac);
	}

	/* Create ingress allow rule */
	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_ALLOW;
	vport->ingress.allow_rule = mlx5_add_flow_rules(vport->ingress.acl, spec,
							&flow_act, NULL, 0);
	if (IS_ERR(vport->ingress.allow_rule)) {
		err = PTR_ERR(vport->ingress.allow_rule);
		esw_warn(esw->dev,
			 "vport[%d] configure ingress allow rule, err(%d)\n",
			 vport->vport, err);
		vport->ingress.allow_rule = NULL;
		goto out;
	}

	memset(&flow_act, 0, sizeof(flow_act));
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP;
	/* Attach drop flow counter */
	counter = vport->ingress.legacy.drop_counter;
	if (counter) {
		flow_act.action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
		drop_ctr_dst.type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
		drop_ctr_dst.counter_id = mlx5_fc_id(counter);
		dst = &drop_ctr_dst;
		dest_num++;
	}
	vport->ingress.legacy.drop_rule =
		mlx5_add_flow_rules(vport->ingress.acl, NULL,
				    &flow_act, dst, dest_num);
	if (IS_ERR(vport->ingress.legacy.drop_rule)) {
		err = PTR_ERR(vport->ingress.legacy.drop_rule);
		esw_warn(esw->dev,
			 "vport[%d] configure ingress drop rule, err(%d)\n",
			 vport->vport, err);
		vport->ingress.legacy.drop_rule = NULL;
		goto out;
	}
	kvfree(spec);
	return 0;

out:
	esw_acl_ingress_lgcy_cleanup(esw, vport);
	kvfree(spec);
	return err;
}

void esw_acl_ingress_lgcy_cleanup(struct mlx5_eswitch *esw,
				  struct mlx5_vport *vport)
{
	if (IS_ERR_OR_NULL(vport->ingress.acl))
		return;

	esw_debug(esw->dev, "Destroy vport[%d] E-Switch ingress ACL\n", vport->vport);

	esw_acl_ingress_lgcy_rules_destroy(vport);
	esw_acl_ingress_lgcy_groups_destroy(vport);
	esw_acl_ingress_table_destroy(vport);
}

void esw_acl_ingress_lgcy_create_counter(struct mlx5_eswitch *esw,
					 struct mlx5_vport *vport)
{
	struct mlx5_fc *counter;

	vport->ingress.legacy.drop_counter = NULL;

	if (!MLX5_CAP_ESW_INGRESS_ACL(esw->dev, flow_counter))
		return;

	counter = mlx5_fc_create(esw->dev, false);
	if (IS_ERR(counter)) {
		esw_warn(esw->dev,
			 "vport[%d] configure ingress drop rule counter failed\n",
			 vport->vport);
		return;
	}

	vport->ingress.legacy.drop_counter = counter;
}

void esw_acl_ingress_lgcy_destroy_counter(struct mlx5_eswitch *esw,
					  struct mlx5_vport *vport)
{
	if (!vport->ingress.legacy.drop_counter)
		return;

	mlx5_fc_destroy(esw->dev, vport->ingress.legacy.drop_counter);
	vport->ingress.legacy.drop_counter = NULL;
}
