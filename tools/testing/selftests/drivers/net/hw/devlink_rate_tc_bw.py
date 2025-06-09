#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""
Devlink Rate TC Bandwidth Test Suite
===================================

This test suite verifies the functionality of devlink-rate traffic class (TC)
bandwidth distribution in a virtualized environment. The tests validate that
bandwidth can be properly allocated between different traffic classes and
that TC mapping works as expected.

Test Environment:
----------------
- Creates 2 VFs
- Establishes a bridge connecting the VFs and their representors
- Sets up VLAN interfaces on each VF with different VLAN IDs (101, 102)
- Configures traffic classes (TC3 and TC4) for bandwidth distribution

Test Cases:
----------
1. test_no_tc_mapping_bandwidth:
   - Verifies that without TC mapping, bandwidth is NOT distributed according to
     the configured 80/20 split between TC4 and TC3
   - This test should fail if bandwidth matches the 80/20 split without TC
      mapping
   - Expected: Bandwidth should NOT be distributed as 80/20

2. test_tc_mapping_bandwidth:
   - Configures TC mapping using mqprio qdisc
   - Verifies that with TC mapping, bandwidth IS distributed according to the
     configured 80/20 split between TC4 and TC3
   - Expected: Bandwidth should be distributed as 80/20 (with 8% tolerance)

Bandwidth Distribution:
----------------------
- TC4 (VF1): Configured for 80% of total bandwidth
- TC3 (VF2): Configured for 20% of total bandwidth
- Total bandwidth: 10G
- Tolerance: ±8% (72-88% for TC4)

Hardware-Specific Behavior (mlx5):
--------------------------
MLX5 hardware enforces traffic class separation by ensuring that each transmit
queue (SQ) is associated with a single TC. If a packet is sent on a queue that
doesn't match the expected TC (based on DSCP or VLAN priority and hypervisor-set
mapping), the hardware moves the queue to the correct TC scheduler to preserve
traffic isolation.

This behavior means that even without explicit TC-to-queue mapping, bandwidth
enforcement may still appear to work—because the hardware dynamically adjusts
the scheduling context. However, this can lead to performance issues in high
rates and HOL blocking if traffic from different TCs is mixed on the same queue.
"""

import time
import os
import subprocess
import re
import threading

from lib.py import (ksft_pr, ksft_run, ksft_exit, KsftSkipEx, KsftXfailEx,
                   KsftFailEx)
from lib.py import ksft_eq, ksft_ge, ksft_lt
from lib.py import EthtoolFamily, NetdevFamily, NetDrvEpEnv
from lib.py import cmd, defer, ethtool, ip
from lib.py import DevlinkFamily


def find_vf_representor_devlink(pf_pci, vf_index):
    try:
        out = subprocess.check_output(['devlink', 'port', 'show'],
                                    encoding='utf-8')
        pattern = re.compile(
            rf'(pci/{pf_pci}/\d+):.*?netdev (\S+).*?vfnum {vf_index}',
            re.DOTALL)
        for line in out.splitlines():
            m = pattern.search(line)
            if m:
                netdev = m.group(2)
                print(f"Representor for VF {vf_index} is {netdev}")
                return netdev
    except Exception as e:
        print(f"Error in find_vf_representor_devlink: {e}")
    return None

def setup_bridge(cfg, vf_interfaces):
    cmd("ip link add name br0 type bridge")
    defer(cmd, "ip link del name br0 type bridge")

    cmd(f"ip link set dev {cfg.ifname} master br0")

    for i in range(len(vf_interfaces)):
        rep_name = find_vf_representor_devlink(cfg.pci, i)
        if rep_name:
            cmd(f"ip link set dev {rep_name} master br0")
            cmd(f"ip link set dev {rep_name} up")
            ksft_pr(f"Set representor {rep_name} up and added to bridge")
        else:
            ksft_pr(f"Could not find representor for VF {i}")

    cmd("ip link set dev br0 up")
    cmd(f"ip link set dev {cfg.ifname} up")
    for vf in vf_interfaces:
        cmd(f"ip link set dev {vf} up")


def setup_vfs(cfg):
    cmd(f"echo 2 > /sys/class/net/{cfg.ifname}/device/sriov_numvfs")
    defer(cmd, f"echo 0 > /sys/class/net/{cfg.ifname}/device/sriov_numvfs")

    time.sleep(2)

    vf_pcis = []
    for i in range(2):
        vf_link = f"/sys/class/net/{cfg.ifname}/device/virtfn{i}"
        vf_pci = os.path.basename(os.path.realpath(vf_link))
        vf_pcis.append(vf_pci)

    for vf_pci in vf_pcis:
        cmd(f"echo {vf_pci} > /sys/bus/pci/drivers/mlx5_core/unbind")

    cmd(f"devlink dev eswitch set pci/{cfg.pci} mode switchdev")

    for vf_pci in vf_pcis:
        cmd(f"echo {vf_pci} > /sys/bus/pci/drivers/mlx5_core/bind")

    time.sleep(2)

    vf_interfaces = []
    for i in range(2):
        vf_name = cmd(
            f"ls /sys/class/net/{cfg.ifname}/device/virtfn{i}/net/"
        ).stdout.strip()
        if vf_name:
            vf_interfaces.append(vf_name)
            ip(f"link set dev {vf_name} up")

    if len(vf_interfaces) != 2:
        raise KsftSkipEx("Failed to create VF interfaces")

    setup_vlan_on_vfs(vf_interfaces)

    return vf_interfaces


def setup_vlan_on_vfs(vf_interfaces):
    vlan_ids = [101, 102]
    tcs = [4, 3]
    ips = ["192.168.101.2", "192.168.102.2"]

    for idx, vf in enumerate(vf_interfaces):
        vlan_dev = f"{vf}.{vlan_ids[idx]}"
        cmd(f"ip link add link {vf} name {vlan_dev} type vlan id {vlan_ids[idx]}")
        cmd(f"ip addr add {ips[idx]}/24 dev {vlan_dev}")
        cmd(f"ip link set dev {vlan_dev} up")
        cmd(f"ip link set dev {vlan_dev} type vlan egress-qos-map 0:{tcs[idx]}")
        ksft_pr(
            f"Created VLAN {vlan_dev} on {vf} with egress-qos-map 0:{tcs[idx]} "
            f"and IP {ips[idx]}"
        )


def get_pf_port_index_from_devlink(pci, pf_netdev):
    out = subprocess.check_output(['devlink', 'port', 'show'], encoding='utf-8')
    pattern_aux = re.compile(
        rf'auxiliary/[\w\.]+/(\d+):.*netdev {pf_netdev}.*flavour physical.*'
        rf'port (\d+)'
    )
    for line in out.splitlines():
        m = pattern_aux.search(line)
        if m:
            return int(m.group(2))
    raise RuntimeError(f"Could not find PF port index for netdev {pf_netdev}")


def get_vf_port_index(pci, vf_index):
    out = subprocess.check_output(['devlink', 'port', 'show'], encoding='utf-8')

    pattern = re.compile(
        rf'pci/{pci}/(\d+):.*?netdev \S+.*?vfnum {vf_index}', re.DOTALL)
    for line in out.splitlines():
        m = pattern.search(line)
        if m:
            port_index = int(m.group(1))
            return port_index
    raise RuntimeError(
        f"Could not find port index for VF {vf_index} in devlink output"
    )


def setup_vfs_in_tc_group(cfg, vf_interfaces):
    devlink = DevlinkFamily()
    for i in range(len(vf_interfaces)):
        port_index = get_vf_port_index(cfg.pci, i)
        devlink.rate_set({
            "bus-name": "pci",
            "dev-name": cfg.pci,
            "port-index": port_index,
            "rate-parent-node-name": "tc_group"
        })


def setup_devlink_rate_with_ynl(cfg, vf_interfaces):
    pf_port_index = get_pf_port_index_from_devlink(cfg.pci, cfg.ifname)
    devlink = DevlinkFamily()
    devlink.rate_new({
        "bus-name": "pci",
        "dev-name": cfg.pci,
        "port-index": pf_port_index,
        "rate-node-name": "tc_group",
        "rate-tx-max": 1250000000,
        "rate-tc-bws": [
            {"rate-tc-index": 0, "rate-tc-bw": 0},
            {"rate-tc-index": 1, "rate-tc-bw": 0},
            {"rate-tc-index": 2, "rate-tc-bw": 0},
            {"rate-tc-index": 3, "rate-tc-bw": 20},
            {"rate-tc-index": 4, "rate-tc-bw": 80},
            {"rate-tc-index": 5, "rate-tc-bw": 0},
            {"rate-tc-index": 6, "rate-tc-bw": 0},
            {"rate-tc-index": 7, "rate-tc-bw": 0},
        ]
    })
    ksft_pr(
        f"Added devlink rate group 'tc_group' on pci/{cfg.pci} PF port "
        f"{pf_port_index} ({cfg.ifname}), tx_max=10G, tc 3=20%, tc 4=80%."
    )

    setup_vfs_in_tc_group(cfg, vf_interfaces)


def run_iperf_client(server_ip, local_ip):
    cmd = ["iperf3", "-c", server_ip, "-B", local_ip, "-t", "10"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr)
        return None
    match = re.search(r'(\d+\.\d+)\s+Gbits/sec', result.stdout)
    if match:
        return float(match.group(1))
    match = re.search(r'(\d+)\s+Mbits/sec', result.stdout)
    if match:
        return float(match.group(1)) / 1000.0
    return None


def setup_remote_server(cfg):
    cmd("ip link add link eth2 name eth2.101 type vlan id 101 || true",
        host=cfg.remote)
    cmd("ip link add link eth2 name eth2.102 type vlan id 102 || true",
        host=cfg.remote)
    cmd("ip addr add 192.168.101.1/24 dev eth2.101 || true", host=cfg.remote)
    cmd("ip addr add 192.168.102.1/24 dev eth2.102 || true", host=cfg.remote)
    cmd("ip link set dev eth2 up", host=cfg.remote)
    cmd("ip link set dev eth2.101 up", host=cfg.remote)
    cmd("ip link set dev eth2.102 up", host=cfg.remote)
    cmd("pkill iperf3 || true", host=cfg.remote)
    cmd("nohup iperf3 -s -B 192.168.101.1 > /tmp/iperf3_101.log 2>&1 &",
        host=cfg.remote)
    cmd("nohup iperf3 -s -B 192.168.102.1 > /tmp/iperf3_102.log 2>&1 &",
        host=cfg.remote)

    defer(cmd, "pkill iperf3 || true", host=cfg.remote)
    defer(cmd, "ip link del eth2.101 || true", host=cfg.remote)
    defer(cmd, "ip link del eth2.102 || true", host=cfg.remote)


def run_iperf_client_thread(server_ip, local_ip, result_list):
    bw = run_iperf_client(server_ip, local_ip)
    result_list.append(bw)


def verify_tc_mapping(dev, expected_tcs):
    try:
        tc_out = cmd(f"tc qdisc show dev {dev}").stdout
        ksft_eq("qdisc" in tc_out, True, f"Qdisc should be configured on {dev}")

        class_out = cmd(f"tc class show dev {dev}").stdout
        for tc in expected_tcs:
            ksft_eq(f"tc {tc}" in class_out, True,
                   f"TC {tc} should be configured on {dev}")

        ksft_pr(f"TC configuration verified on {dev}")
        return True
    except Exception as e:
        ksft_pr(f"TC mapping verification failed for {dev}: {str(e)}")
        return False


def calculate_bandwidth_percentages(bandwidths):
    tc4_bw = bandwidths[0]
    tc3_bw = bandwidths[1]
    total_bw = tc3_bw + tc4_bw
    tc4_percentage = (tc4_bw / total_bw) * 100
    tc3_percentage = (tc3_bw / total_bw) * 100

    return {
        'tc4_bw': tc4_bw,
        'tc3_bw': tc3_bw,
        'tc4_percentage': tc4_percentage,
        'tc3_percentage': tc3_percentage
    }


def run_bandwidth_test(vf_interfaces):
    vf_vlan_ips = [
        (f"{vf_interfaces[0]}.101", "192.168.101.2", "192.168.101.1"),
        (f"{vf_interfaces[1]}.102", "192.168.102.2", "192.168.102.1"),
    ]

    bandwidths = []
    threads = []
    start_barrier = threading.Barrier(len(vf_vlan_ips))

    def run_thread(remote_ip, local_ip, bandwidths):
        start_barrier.wait()
        run_iperf_client_thread(remote_ip, local_ip, bandwidths)

    for vlan_dev, local_ip, remote_ip in vf_vlan_ips:
        t = threading.Thread(target=run_thread,
                           args=(remote_ip, local_ip, bandwidths))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return bandwidths


def setup_test_environment(cfg):
    vf_interfaces = setup_vfs(cfg)
    ksft_pr(f"Created VF interfaces: {vf_interfaces}")

    setup_bridge(cfg, vf_interfaces)
    ksft_pr("Set up bridge")

    setup_devlink_rate_with_ynl(cfg, vf_interfaces)
    setup_remote_server(cfg)
    time.sleep(2)

    return vf_interfaces


def print_bandwidth_results(bw_data, test_name):
    ksft_pr(f"\nBandwidth check results for {test_name}:")
    ksft_pr(f"TC 4 (VF1): {bw_data['tc4_bw']:.2f} Gbits/sec")
    ksft_pr(f"TC 3 (VF2): {bw_data['tc3_bw']:.2f} Gbits/sec")
    ksft_pr(f"TC 4 percentage: {bw_data['tc4_percentage']:.1f}%")


def test_no_tc_mapping_bandwidth(cfg):
    vf_interfaces = setup_test_environment(cfg)
    bandwidths = run_bandwidth_test(vf_interfaces)
    bw_data = calculate_bandwidth_percentages(bandwidths)
    print_bandwidth_results(bw_data, "without TC mapping")

    if 72 <= bw_data['tc4_percentage'] <= 88:
        raise KsftFailEx("Bandwidth matched 80/20 split without TC mapping")
    else:
        ksft_pr("Bandwidth is NOT distributed as 80/20 without TC mapping")
        return True


def test_tc_mapping_bandwidth(cfg):
    vf_interfaces = setup_test_environment(cfg)

    for vf in vf_interfaces:
        cmd(f"tc qdisc del dev {vf} root || true")
        cmd(f"tc qdisc add dev {vf} root handle 5 mqprio mode dcb hw 1 "
            f"num_tc 8")

    bandwidths = run_bandwidth_test(vf_interfaces)
    bw_data = calculate_bandwidth_percentages(bandwidths)
    print_bandwidth_results(bw_data, "with TC mapping")

    if 72 <= bw_data['tc4_percentage'] <= 88:
        ksft_pr("Bandwidth is distributed as 80/20 with TC mapping")
        return True
    else:
        ksft_pr("Bandwidth is NOT distributed as 80/20 with TC mapping!")
        raise KsftFailEx(
            "Bandwidth did not match 80/20 split with TC mapping - "
            "this should happen!"
        )


def main() -> None:
    with NetDrvEpEnv(__file__, nsim_test=False) as cfg:
        cfg.ethnl = EthtoolFamily()
        cfg.netnl = NetdevFamily()

        cfg.pci = cmd(
            f"ethtool -i {cfg.ifname} | grep bus-info | cut -d' ' -f2"
        ).stdout.strip()
        if not cfg.pci:
            raise KsftSkipEx("Could not get PCI address of the interface")

        cases = [test_no_tc_mapping_bandwidth, test_tc_mapping_bandwidth]

        ksft_run(cases=cases, args=(cfg,))
    ksft_exit()


if __name__ == "__main__":
    main()