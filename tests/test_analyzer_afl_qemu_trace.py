import contextlib
import signal
import archr
import os
import unittest

from common import build_container


class TestAnalyzerQemu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ...

    def test_implant_injection_local(self):
        with archr.targets.LocalTarget(
            [os.path.join(os.path.dirname(__file__), "dockers", "crasher", "crasher")]
        ).build().start() as t:
            archr.analyzers.AFLQEMUTracerAnalyzer(t)
            fire_path = os.path.join(t.tmpwd, "afl_qemu_trace", "fire")
            assert t.retrieve_contents(fire_path).startswith(b"#!/bin/sh")

    def crasher_checks(self, t):
        b = archr.analyzers.AFLQEMUTracerAnalyzer(t)
        r = b.fire(save_core=True)

        # arbitrary check
        assert len(r.trace) > 100, "Trace is too short"
        assert not r.timed_out, "Trace timed out"
        assert r.crashed, "Trace did not crash"
        assert r.signal == signal.SIGSEGV, "Crash signal is wrong"
        assert r.image_base, "Image base is not set"
        assert r.entry_point, "Entry point is not set"

    def crash_on_input_checks(self, t):
        crashing = b"A" * 120
        b = archr.analyzers.AFLQEMUTracerAnalyzer(t)
        with b.fire_context(save_core=True) as flight:
            flight.default_channel.send(crashing)
            flight.default_channel.shutdown_wr()
            # flight.default_channel.recvall()

        assert flight.result.crashed

    def shellcode_checks(self, t):
        crash = b"A" * 272
        b = archr.analyzers.AFLQEMUTracerAnalyzer(t)

        with b.fire_context(save_core=True) as flight:
            flight.default_channel.send(crash)
            flight.default_channel.shutdown_wr()
            # flight.default_channel.recvall()

        assert not flight.result.timed_out
        assert flight.result.crashed

    def vuln_stacksmash_checks(self, t):
        crash = b"A" * 227

        b = archr.analyzers.AFLQEMUTracerAnalyzer(t)

        with b.fire_context(save_core=True) as flight:
            flight.default_channel.send(crash)
            flight.default_channel.shutdown_wr()
            # flight.default_channel.recvall()

        assert not flight.result.timed_out
        assert flight.result.crashed

    def file_maps_checks(self, t):
        b = archr.analyzers.AFLQEMUTracerAnalyzer(t)
        r = b.fire(record_file_maps=True)

        # check for the explicitly mapped file
        assert "mapped_file" in r.mapped_files.keys()
        assert r.mapped_files["mapped_file"][0]

        # check for shared library mapping
        assert "libc.so.6" in r.mapped_files.keys()
        assert r.mapped_files["libc.so.6"][0]

    def test_crasher_trace_local(self):
        with archr.targets.LocalTarget(
            [
                os.path.realpath(
                    os.path.join(
                        os.path.dirname(__file__), "dockers", "crasher", "crasher"
                    )
                )
            ]
        ).build().start() as t:
            self.crasher_checks(t)

    def test_file_maps_local(self):
        with archr.targets.LocalTarget(
            [
                os.path.realpath(
                    os.path.join(
                        os.path.dirname(__file__), "dockers", "file_maps", "file_maps"
                    )
                )
            ],
            target_cwd=os.path.realpath(
                os.path.join(os.path.dirname(__file__), "dockers", "file_maps")
            ),
        ).build().start() as t:
            self.file_maps_checks(t)


if __name__ == "__main__":
    unittest.main()
