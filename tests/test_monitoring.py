"""Test monitoring behavior."""

from datetime import timedelta

from atlaso.app.models import utcnow
from sqlalchemy import select

from atlaso.app.config import get_settings
from atlaso.app.models import MonitorSample
from atlaso.app.services.monitoring import (
    CpuCoreCounters,
    CpuCounters,
    DiskUsage,
    MonitorSnapshot,
    NetworkCounters,
    cpu_percent,
    monitor_payload,
    parse_diskstats,
    parse_meminfo,
    parse_net_dev,
    parse_proc_stat_cpu,
    parse_proc_stat_cpus,
    record_monitor_sample,
)


class FakeMonitorCollector:
    """Represent fake monitor collector.

    Attributes:
        snapshots: Snapshots captured or supplied by this test helper.
    """
    def __init__(self, snapshots):
        """Initialize the fake monitor collector.

        Args:
            snapshots: Snapshots supplied to the test scenario.
        """
        self.snapshots = list(snapshots)

    def collect(self, sampled_at=None):
        """Return collect.

        Args:
            sampled_at: Sampled at supplied to the test scenario.


        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        if self.snapshots:
            return self.snapshots.pop(0)
        raise AssertionError("Unexpected monitor collection")

    def collect_virtualization(self):
        """Return collect virtualization."""
        return {
            "detected": "vmware",
            "sys_vendor": "VMware, Inc.",
            "product_name": "VMware Virtual Platform",
            "vmtools_version": "VMware Tools 13.0",
            "hostname": "atlaso-test",
            "platform": "Linux-test",
        }


def test_monitor_parsers_handle_linux_proc_shapes():
    """Verify that monitor parsers handle linux proc shapes."""
    proc_stat = "cpu  100 0 50 850 25 0 0 0\ncpu0 10 0 5 85 0 0 0 0\ncpu1 20 0 10 70 0 0 0 0\n"
    cpu = parse_proc_stat_cpu(proc_stat)
    assert cpu == CpuCounters(total=1025, idle=875)
    assert parse_proc_stat_cpus(proc_stat) == [
        CpuCoreCounters(name="cpu0", total=100, idle=85),
        CpuCoreCounters(name="cpu1", total=100, idle=70),
    ]
    assert cpu_percent(CpuCounters(total=1000, idle=900), CpuCounters(total=1100, idle=950)) == 50.0

    memory = parse_meminfo("MemTotal:       2048 kB\nMemAvailable:   512 kB\nSwapTotal:      128 kB\nSwapFree:        64 kB\n")
    assert memory["MemTotal"] == 2_097_152
    assert memory["MemAvailable"] == 524_288

    networks = parse_net_dev("  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n")
    assert networks[0].name == "eth0"
    assert networks[0].rx_bytes == 1000
    assert networks[0].tx_dropped == 4

    disks = parse_diskstats("   8       0 sda 1 0 8 0 2 0 16 0 0 0 0 0 0 0 0 0\n")
    assert disks["sda"].read_bytes == 4096
    assert disks["sda"].write_bytes == 8192


def test_monitor_samples_persist_rates_and_payload(client, monkeypatch):
    """Verify that monitor samples persist rates and payload.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.database import SessionLocal

    now = utcnow()
    snapshots = [
        MonitorSnapshot(
            sampled_at=now - timedelta(seconds=30),
            cpu=CpuCounters(total=1000, idle=900),
            cpus=[CpuCoreCounters(name="cpu0", total=500, idle=450), CpuCoreCounters(name="cpu1", total=500, idle=450)],
            cpu_count=4,
            load=(0.25, 0.2, 0.1),
            memory_total_bytes=8_000,
            memory_available_bytes=4_000,
            memory_used_percent=50.0,
            swap_total_bytes=1_000,
            swap_used_bytes=100,
            networks=[NetworkCounters(name="eth0", rx_bytes=1_000, tx_bytes=2_000, rx_packets=10, tx_packets=20, rx_errors=0, tx_errors=0, rx_dropped=0, tx_dropped=0, oper_state="up")],
            disks=[
                DiskUsage(mount_point="/", device="/dev/sda1", filesystem="ext4", total_bytes=10_000, used_bytes=4_000, free_bytes=6_000, used_percent=40.0, read_bytes=1_000, write_bytes=2_000),
                DiskUsage(mount_point="/etc", device="/dev/sda1", filesystem="ext4", total_bytes=10_000, used_bytes=4_000, free_bytes=6_000, used_percent=40.0, read_bytes=1_000, write_bytes=2_000),
                DiskUsage(mount_point="/data", device="/dev/sdb1", filesystem="xfs", total_bytes=20_000, used_bytes=5_000, free_bytes=15_000, used_percent=25.0, read_bytes=500, write_bytes=1_000),
                DiskUsage(mount_point="/sys/fs/selinux", device="selinuxfs", filesystem="selinuxfs", total_bytes=0, used_bytes=0, free_bytes=0, used_percent=None),
            ],
        ),
        MonitorSnapshot(
            sampled_at=now,
            cpu=CpuCounters(total=1100, idle=950),
            cpus=[CpuCoreCounters(name="cpu0", total=550, idle=470), CpuCoreCounters(name="cpu1", total=550, idle=480)],
            cpu_count=4,
            load=(0.5, 0.3, 0.2),
            memory_total_bytes=8_000,
            memory_available_bytes=3_000,
            memory_used_percent=62.5,
            swap_total_bytes=1_000,
            swap_used_bytes=125,
            networks=[NetworkCounters(name="eth0", rx_bytes=1_900, tx_bytes=2_600, rx_packets=19, tx_packets=26, rx_errors=1, tx_errors=0, rx_dropped=0, tx_dropped=1, oper_state="up")],
            disks=[
                DiskUsage(mount_point="/", device="/dev/sda1", filesystem="ext4", total_bytes=10_000, used_bytes=5_000, free_bytes=5_000, used_percent=50.0, read_bytes=1_600, write_bytes=3_200),
                DiskUsage(mount_point="/etc", device="/dev/sda1", filesystem="ext4", total_bytes=10_000, used_bytes=5_000, free_bytes=5_000, used_percent=50.0, read_bytes=1_600, write_bytes=3_200),
                DiskUsage(mount_point="/data", device="/dev/sdb1", filesystem="xfs", total_bytes=20_000, used_bytes=6_000, free_bytes=14_000, used_percent=30.0, read_bytes=800, write_bytes=1_600),
                DiskUsage(mount_point="/sys/fs/selinux", device="selinuxfs", filesystem="selinuxfs", total_bytes=0, used_bytes=0, free_bytes=0, used_percent=None),
            ],
        ),
    ]

    with SessionLocal() as db:
        collector = FakeMonitorCollector(snapshots)
        record_monitor_sample(db, collector=collector)
        second = record_monitor_sample(db, collector=collector)
        assert second.cpu_percent == 50.0
        assert [row.percent for row in second.cpu_samples] == [60.0, 40.0]
        assert second.network_samples[0].rx_bytes_per_sec == 30.0
        assert second.disk_samples[0].write_bytes_per_sec == 40.0

        monkeypatch.setattr(get_settings(), "monitor_enabled", True)
        payload = monitor_payload(db, hours=6, collector=FakeMonitorCollector([]))

    assert payload["summary"]["cpu"]["current_percent"] == 50.0
    assert [row["name"] for row in payload["cpu_cores"]] == ["cpu0", "cpu1"]
    assert [row["current_percent"] for row in payload["cpu_cores"]] == [60.0, 40.0]
    assert payload["cpu_cores"][0]["points"][-1]["percent"] == 60.0
    assert payload["summary"]["memory"]["current_percent"] == 62.5
    assert payload["summary"]["network"]["rx_bytes_per_sec"] == 30.0
    assert payload["summary"]["disk"]["highest_used_mount"] == "/"
    assert payload["disk_io"][-1]["read_bytes_per_sec"] == 30.0
    assert payload["disk_io"][-1]["write_bytes_per_sec"] == 60.0
    assert [row["device"] for row in payload["disk_devices"]] == ["/dev/sda1", "/dev/sdb1"]
    assert "/sys/fs/selinux" not in [row["mount_point"] for row in payload["disks"]]
    assert payload["disk_devices"][0]["points"][-1]["write_bytes_per_sec"] == 40.0
    assert payload["disk_devices"][0]["points"][-1]["used_percent"] == 50.0
    assert payload["disk_devices"][1]["used_percent"] == 30.0
    assert payload["disk_devices"][1]["points"][-1]["read_bytes_per_sec"] == 10.0
    assert payload["virtualization"]["detected"] == "vmware"
    assert payload["server_time"] == payload["generated_at"]


def test_monitor_payload_disabled_does_not_collect_or_write(client):
    """Verify that monitor payload disabled does not collect or write.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        payload = monitor_payload(db, hours=6, collector=FakeMonitorCollector([]))
        sample_count = db.execute(select(MonitorSample)).scalars().all()

    assert payload["enabled"] is False
    assert payload["sample_count"] == 0
    assert payload["server_time"] == payload["generated_at"]
    assert payload["virtualization"]["detected"] == "disabled"
    assert sample_count == []
