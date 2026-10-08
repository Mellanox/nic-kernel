#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""
PSP HW GRO conformance tests.

This reuses the gro binary in PSP mode:
The sender crafts encapsulated & SW-encrypted PSP packets with receiver's PSP
rx-assoc, and the receiver's device decrypts and decapsulates the packets
before an AF_PACKET tap gets to analyze them.

All GRO conformance tests which could run with PSP are included.
"""

import socket

from gro_lib import gro_variants, run_test
from psp_lib import init_psp_dev, require_version

from lib.py import ksft_run, ksft_exit
from lib.py import ksft_variants, KsftNamedVariant
from lib.py import NetDrvEpEnv, PSPFamily
from lib.py import defer


def _psp_variants():
    for ver in range(4):
        for proto, test_name in gro_variants():
            if proto not in ("ipv4", "ipv6"):
                continue
            # PSP doesn't support IPv6 extension headers.
            if test_name in ("ip_v6ext_same", "ip_v6ext_diff"):
                continue
            yield KsftNamedVariant(f"v{ver}_{proto}_{test_name}",
                                   ver, proto, test_name)


def _ip_variants():
    """IPv4/IPv6."""
    for proto in ("ipv4", "ipv6"):
        yield KsftNamedVariant(proto, proto)


def _psp_assoc(cfg, version=0):
    # This socket receives no traffic, exists solely to own the rx assoc.
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    defer(s.close)
    return cfg.pspnl.rx_assoc({"version": version, "dev-id": cfg.psp_dev_id,
                               "sock-fd": s.fileno()})['rx-key']


def _setup(cfg, version):
    """Enables PSP on the device under test."""
    cfg.require_nsim(nsim_test=False)
    init_psp_dev(cfg)
    require_version(cfg, version)


def _psp_args(cfg, versions):
    """Produces PSP associations as gro binary --psp-assoc arguments."""
    keys = [_psp_assoc(cfg, ver) for ver in versions]
    return [f"--psp-assoc {ver},{key['spi']:x},{key['key'].hex()}"
            for ver, key in zip(versions, keys)]


def _run(cfg, test_name, protocol, versions):
    """Sets up, associates and runs one gro test case under PSP + HW GRO."""
    _setup(cfg, max(versions))

    run_test(cfg, "hw", protocol, test_name,
             common_args=_psp_args(cfg, versions))


@ksft_variants(_psp_variants())
def test_psp_gro(cfg, version, protocol, test_name):
    """Runs one gro conformance case with PSP encapsulation."""
    _run(cfg, test_name, protocol, [version])


# PSP-specific GRO tests

@ksft_variants(_ip_variants())
def test_psp_spi_diff(cfg, protocol):
    """Frames from two different SPIs must not coalesce."""
    _run(cfg, "psp_spi_diff", protocol, [0, 0])


@ksft_variants(_ip_variants())
def test_psp_ver_diff(cfg, protocol):
    """Frames from two different PSP versions are decapped and not coalesced."""
    _run(cfg, "psp_ver_diff", protocol, [0, 1])


@ksft_variants(_ip_variants())
def test_psp_mixed(cfg, protocol):
    """A PSP frame must not coalesce with a clear text one."""
    _run(cfg, "psp_mixed", protocol, [0])


@ksft_variants(_ip_variants())
def test_psp_after_reconfig(cfg, protocol):
    """Verifies that decap still works after PSP off + on."""
    _setup(cfg, 0)

    cap = cfg.psp_info['psp-versions-cap']
    cfg.pspnl.dev_set({'id': cfg.psp_dev_id, 'psp-versions-ena': []})
    cfg.pspnl.dev_set({'id': cfg.psp_dev_id, 'psp-versions-ena': cap})

    run_test(cfg, "hw", protocol, "data_same",
             common_args=_psp_args(cfg, [0]))


def main() -> None:
    """ Ksft boiler plate main """

    with NetDrvEpEnv(__file__) as cfg:
        cfg.pspnl = PSPFamily()

        ksft_run(cases=[test_psp_gro, test_psp_spi_diff, test_psp_ver_diff,
                        test_psp_mixed, test_psp_after_reconfig],
                 args=(cfg, ))
    ksft_exit()


if __name__ == "__main__":
    main()
