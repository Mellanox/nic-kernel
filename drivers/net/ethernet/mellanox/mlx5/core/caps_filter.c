// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include "linux/mlx5/device.h"
#include <linux/mlx5/driver.h>
#include <linux/mlx5/qp.h>
#include "mlx5_core.h"

#define MLX5_HCA_CAP_ALLOW(cap, fld) \
	MLX5_SET(cap, dst, fld, MLX5_GET(cap, src, fld))
#define MLX5_HCA_CAP_ALLOW64(cap, fld) \
	MLX5_SET64(cap, dst, fld, MLX5_GET64(cap, src, fld))

/* Allow a numeric capability range restricted to [lo, hi]. */
#define MLX5_HCA_CAP_CLAMP(cap, fld, lo, hi) \
	MLX5_SET(cap, dst, fld, mlx5_cap_clamp(dev, #fld, \
					       MLX5_GET(cap, src, fld), \
					       (lo), (hi)))

/* Check cap range and return error otherwise. */
#define MLX5_HCA_CAP_CHECK(cap, fld, lo, hi) \
	mlx5_cap_check(dev, #fld, MLX5_GET(cap, dst, fld), (lo), (hi), false)
/* Same but zero is also a valid value. */
#define MLX5_HCA_CAP_CHECK_Z(cap, fld, lo, hi) \
	mlx5_cap_check(dev, #fld, MLX5_GET(cap, dst, fld), (lo), (hi), true)

static u32 mlx5_cap_clamp(struct mlx5_core_dev *dev, const char *name,
			  u32 val, u32 lo, u32 hi)
{
	u32 clamped = clamp_t(u32, val, lo, hi);

	if (clamped != val)
		mlx5_core_warn(dev, "cap filter: FW reported %s=%u, outside [%u, %u], using %u\n",
			       name, val, lo, hi, clamped);

	return clamped;
}

static int mlx5_cap_check(struct mlx5_core_dev *dev, const char *name,
			  u32 val, u32 lo, u32 hi, bool zero)
{
	if (val >= lo && val <= hi)
		return 0;

	if (zero && !val)
		return 0;

	mlx5_core_err(dev, "cap filter: FW reported %s=%u, outside [%u, %u] %s\n",
		      name, val, lo, hi,
		      zero ? "or 0" : "");

	return -EINVAL;
}

static int mlx5_adversarial_filter_general(struct mlx5_core_dev *dev, void *dst,
					   void *src)
{
	int err;

	memset(dst, 0, MLX5_UN_SZ_BYTES(hca_cap_union));

	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, page_request_disable);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vhca_resource_manager);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, hca_cap_2);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, event_on_vhca_state_teardown_request);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, event_on_vhca_state_in_use);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, event_on_vhca_state_active);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, event_on_vhca_state_allocated);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, event_on_vhca_state_invalid);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vhca_id);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_srq_sz);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_qp_sz);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, event_cap);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_qp);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_srq);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_sgl_for_optimized_performance);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_cq_sz);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, order_write_after_write_umr);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, pci_relaxed_ordered_read_umr);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_cq);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, mkc_order_write_after_write_ro);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, relaxed_ordering_read_pci_enabled);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_mkey);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, terminate_scatter_list_mkey);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, fast_teardown);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_eq);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_indirection);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, fixed_buffer_size);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, force_teardown);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, umr_extended_translation_offset);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_klm_list_size);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, qpc_extension);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_ra_req_dc);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vnic_env_cq_overrun);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_ra_res_dc);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, release_all_pages);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, roce_accl);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_ra_req_qp);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_ra_res_qp);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, end_pad);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, cc_query_allowed);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, cc_modify_allowed);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, cache_line_128byte);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, rts2rts_qp_counters_set_id);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vnic_env_int_rq_oob);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, sbcam_reg);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, qcam_reg);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, gid_table_size);

	/* Values outside of [0, 4] range are unexpected. */
	err = MLX5_HCA_CAP_CHECK(cmd_hca_cap, gid_table_size, 0, 4);
	if (err)
		return err;

	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, out_of_seq_cnt);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vport_counters);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, retransmission_q_counters);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, debug);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, modify_rq_counter_set_id);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, rq_delay_drop);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_qp_cnt);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, pkey_table_size);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vport_group_manager);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vnic_env_queue_counters);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, ets);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, nic_flow_table);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, mcam_reg);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, pcam_reg);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, local_ca_ack_delay);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, enhanced_error_q_counters);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, beacon_led);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, port_type);
	/* 0 is invalid, 8 is for MLX5_MAX_PORTS */
	MLX5_HCA_CAP_CLAMP(cmd_hca_cap, num_ports, 1, 8);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_msg);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_tc);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, dcbx);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, general_notification_event);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, stat_rate_support);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, pci_sync_for_fw_update_event);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, cqe_version);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, umr_modify_entity_size_disabled);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, umr_modify_atomic_disabled);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, umr_indirect_mkey_disabled);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, umr_fence);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, cmdif_checksum);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, sho);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, qos);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, eth_net_offloads);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, roce);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, atomic);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, cq_moderation);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, cq_period_mode_modify);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, cq_period_start_from_cqe);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, apm);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, umr_ptr_rlky);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, qp_packet_based);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, pkv);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, rc);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, uar_4k);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, fl_rc_qp_when_roce_disabled);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_pg_sz);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, bf);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, driver_version);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, mkey_by_name);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_bf_reg_size);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, disciplined_fr_counter);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, qp_error_syndrome);
	MLX5_HCA_CAP_CLAMP(cmd_hca_cap, num_lag_ports, 0, 1);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_wqe_sz_sq);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, icm_mng_function_id_mode);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, tis_tir_td_order);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_wqe_sz_rq);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, query_host_net_function_num_max);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_qp_mcg);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_mcg);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_transport_domain);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, pci_relaxed_ordered_read);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_pd);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, dp_ordering_ooo_all_ud);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, dp_ordering_ooo_all_uc);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, dp_ordering_ooo_all_xrc);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, dp_ordering_ooo_all_dc);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, dp_ordering_ooo_all_rc);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, pcie_reset_using_hotreset_method);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap,
			   pci_sync_for_fw_update_with_driver_unload);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vnic_env_cnt_steering_fail);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vport_counter_local_loopback);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, q_counter_aggregation);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, q_counter_other_vport);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, nic_receive_steering_discard);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, receive_discard_vport_down);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, transmit_discard_vport_down);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, eq_overrun_count);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, invalid_command_count);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, quota_exceeded_count);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_flow_counter_bulk);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_rq);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_sq);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_tir);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, basic_cyclic_rcv_wqe);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_rqt);
	MLX5_HCA_CAP_CLAMP(cmd_hca_cap, log_max_rqt_size, 0, 13);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vnic_env_cnt_bar_uar_access);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vnic_env_cnt_odp_page_fault);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, roce_rw_supported);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_wq_sz);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, vhca_state);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_vlan_list);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_current_mc_list);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_current_uc_list);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, sq_ts_format);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, rq_ts_format);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, steering_format_version);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, create_qp_start_hint);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, ats);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, cross_vhca_rqt);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_uctx);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_num_eqs);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_uar_page_sz);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_geneve_tlv_options);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_geneve_tlv_option_data_len);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_dci_stream_channels);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, log_max_dci_errored_streams);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, crossing_vhca_mkey);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, native_port_num);
	MLX5_HCA_CAP_CLAMP(cmd_hca_cap, num_vhca_ports, 0, 1);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, sw_owner_id);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_num_of_monitor_counters);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, num_ppcnt_monitor_counters);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, num_q_monitor_counters);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, apu);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, uctx_cap);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, num_total_dynamic_vf_msix);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, min_dynamic_vf_msix_table_size);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, data_direct);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, max_dynamic_vf_msix_table_size);
	MLX5_HCA_CAP_ALLOW64(cmd_hca_cap, vhca_tunnel_commands);

	MLX5_SET(cmd_hca_cap, dst, num_of_uars_per_page, MLX5_UARS_IN_PAGE);

	MLX5_HCA_CAP_ALLOW(cmd_hca_cap, flow_counter_bulk_alloc);

	err = MLX5_HCA_CAP_CHECK(cmd_hca_cap, log_pg_sz,
				 MLX5_ADAPTER_PAGE_SHIFT,
				 MLX5_ADAPTER_PAGE_SHIFT);
	if (err)
		return err;

#define LOG_BF_REG_SIZE_MIN ilog2(2 * MLX5_SEND_WQE_BB)
#define LOG_BF_REG_SIZE_MAX \
	ilog2((MLX5_ADAPTER_PAGE_SIZE - MLX5_BF_OFFSET) / MLX5_BFREGS_PER_UAR)

	err = MLX5_HCA_CAP_CHECK(cmd_hca_cap, log_bf_reg_size,
				 LOG_BF_REG_SIZE_MIN,
				 LOG_BF_REG_SIZE_MAX);
	if (err)
		return err;

#undef LOG_BF_REG_SIZE_MAX
#undef LOG_BF_REG_SIZE_MIN

	return MLX5_HCA_CAP_CHECK(cmd_hca_cap, min_dynamic_vf_msix_table_size, 0,
				  MLX5_GET(cmd_hca_cap, dst,
					   max_dynamic_vf_msix_table_size));
}

static int mlx5_adversarial_filter_general_2(struct mlx5_core_dev *dev, void *dst,
					     void *src)
{
	int err;
	u32 val;

	memset(dst, 0, MLX5_UN_SZ_BYTES(hca_cap_union));

	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, dp_ordering_force);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, query_vuid);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, umr_log_entity_size_5);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, max_reformat_insert_size);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, max_reformat_insert_offset);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, max_reformat_remove_size);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, max_reformat_remove_offset);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, sf_eq_usage);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, max_rqt_vhca_id);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2,
			   min_mkey_log_entity_size_fixed_buffer_valid);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, log_min_mkey_entity_size);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2,
			   min_mkey_log_entity_size_fixed_buffer);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2,
			   max_mkey_log_entity_size_fixed_buffer);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, max_mkey_log_entity_size_mtt);
	MLX5_HCA_CAP_ALLOW(cmd_hca_cap_2, max_num_eqs_24b);

	err = MLX5_HCA_CAP_CHECK_Z(cmd_hca_cap_2, max_mkey_log_entity_size_mtt,
				   MLX5_ADAPTER_PAGE_SHIFT, 63);
	if (err)
		return err;

	err = MLX5_HCA_CAP_CHECK_Z(cmd_hca_cap_2,
				   max_mkey_log_entity_size_fixed_buffer,
				   MLX5_ADAPTER_PAGE_SHIFT, 63);
	if (err)
		return err;

	val = MLX5_GET(cmd_hca_cap_2, dst, max_mkey_log_entity_size_mtt) ?: 31;
	err = MLX5_HCA_CAP_CHECK(cmd_hca_cap_2, log_min_mkey_entity_size, 0,
				 val);
	if (err)
		return err;

	/* The fixed buffer min is don't-care when its valid bit is clear. */
	if (!MLX5_GET(cmd_hca_cap_2, dst,
		      min_mkey_log_entity_size_fixed_buffer_valid))
		return 0;

	val = MLX5_GET(cmd_hca_cap_2, dst,
		       max_mkey_log_entity_size_fixed_buffer) ?: 31;
	return MLX5_HCA_CAP_CHECK(cmd_hca_cap_2,
				  min_mkey_log_entity_size_fixed_buffer, 0, val);
}

static int mlx5_adversarial_filter_per_protocol(struct mlx5_core_dev *dev,
						 void *dst, void *src)
{
	memset(dst, 0, MLX5_UN_SZ_BYTES(hca_cap_union));

	MLX5_HCA_CAP_ALLOW(per_protocol_networking_offload_caps, csum_cap);
	MLX5_HCA_CAP_ALLOW(per_protocol_networking_offload_caps, vlan_cap);
	MLX5_HCA_CAP_ALLOW(per_protocol_networking_offload_caps,
			   self_lb_en_modifiable);
	MLX5_HCA_CAP_ALLOW(per_protocol_networking_offload_caps, max_lso_cap);
	MLX5_HCA_CAP_ALLOW(per_protocol_networking_offload_caps,
			   wqe_inline_mode);
	MLX5_HCA_CAP_ALLOW(per_protocol_networking_offload_caps,
			   rss_ind_tbl_cap);
	MLX5_HCA_CAP_ALLOW(per_protocol_networking_offload_caps,
			   cqe_checksum_full);
	MLX5_HCA_CAP_ALLOW(per_protocol_networking_offload_caps,
			   max_vxlan_udp_ports);

	return 0;
}

#undef MLX5_HCA_CAP_ALLOW
#undef MLX5_HCA_CAP_ALLOW64
#undef MLX5_HCA_CAP_CLAMP
#undef MLX5_HCA_CAP_CHECK
#undef MLX5_HCA_CAP_CHECK_Z

int mlx5_store_caps(struct mlx5_core_dev *dev, enum mlx5_cap_type cap_type,
		    void *dst, void *src)
{
	if (!mlx5_is_adversarial()) {
		memcpy(dst, src, MLX5_UN_SZ_BYTES(hca_cap_union));
		return 0;
	}

	switch (cap_type) {
	case MLX5_CAP_GENERAL:
		return mlx5_adversarial_filter_general(dev, dst, src);
	case MLX5_CAP_GENERAL_2:
		return mlx5_adversarial_filter_general_2(dev, dst, src);
	case MLX5_CAP_ETHERNET_OFFLOADS:
		return mlx5_adversarial_filter_per_protocol(dev, dst, src);

	case MLX5_CAP_ATOMIC:
	case MLX5_CAP_ROCE:
	case MLX5_CAP_FLOW_TABLE:
	case MLX5_CAP_DEV_EVENT:
		memcpy(dst, src, MLX5_UN_SZ_BYTES(hca_cap_union));
		break;

	default:
		memset(dst, 0, MLX5_UN_SZ_BYTES(hca_cap_union));
		break;
	}

	return 0;
}
