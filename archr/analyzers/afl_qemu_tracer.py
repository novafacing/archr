from contextlib import contextmanager, suppress
from glob import glob
from logging import getLogger
from os.path import join
from io import BytesIO
from re import compile, search
from shutil import move, rmtree
from signal import SIGILL, SIGSEGV
from subprocess import TimeoutExpired
from tempfile import mkdtemp, mktemp
from archr.analyzers import ContextAnalyzer
from archr.analyzers.qemu_tracer import (
    QEMUTracerError,
    QemuTraceResult,
)
from archr.utils import filter_strace_output, get_file_maps

l = getLogger("archr.analyzers.afl_qemu_tracer")
_trace_old_re = compile(br"Trace (.*) \[(?P<addr>.*)\].*")
_trace_new_re = compile(
    br"Trace (.*) \[(?P<something1>.*)\/(?P<addr>.*)\/(?P<flags>.*)\].*"
)


class AFLQEMUTracerAnalyzer(ContextAnalyzer):
    """
    afl-qemu-trace analyzer
    """

    REQUIRED_IMPLANT = "afl_qemu_trace"

    def __init__(
        self,
        target,
        timeout=10,
        ld_linux=None,
        ld_preload=None,
        library_path=None,
        seed=None,
        **kwargs,
    ):
        """
        Initialize AFLQEMUTracerAnalyzer

        :param target: target binary to analyze
        :param timeout: timeout for the analysis
        :param ld_linux: path to the linux dynamic linker
        :param ld_preload: path to the preload library
        :param library_path: path to the library to load
        :param seed: seed to use for the analysis
        :param kwargs: additional arguments to pass to the QEMUTracerAnalyzer
        """
        super().__init__(target, **kwargs)

        self.timeout = timeout
        self.ld_linux = ld_linux
        self.ld_preload = ld_preload
        self.library_path = library_path
        self.seed = seed

    def pickup_env(self):
        for e in self.target.target_env:
            key, value = e.split("=", 1)
            if key == "LD_PRELOAD" and self.ld_preload is None:
                self.ld_preload = value
            if key == "LD_LIBRARY_PATH" and self.library_path is None:
                self.library_path = value

    @contextmanager
    def _target_mk_tmpdir(self):
        tmpdir = mktemp(prefix="/tmp/tracer_target_")
        self.target.run_command(["mkdir", tmpdir]).wait()
        self.target.run_command(["chmod", "777", tmpdir]).wait()
        try:
            yield tmpdir
        finally:
            self.target.run_command(["rm", "-rf", tmpdir])

    @staticmethod
    @contextmanager
    def _local_mk_tmpdir():
        tmpdir = mkdtemp(prefix="/tmp/tracer_local_")
        try:
            yield tmpdir
        finally:
            with suppress(FileNotFoundError):
                rmtree(tmpdir)

    @staticmethod
    def line_iter(content):
        io = BytesIO(content)
        for line in io:
            yield line.strip()

    @contextmanager
    def fire_context(
        self,
        record_trace=True,
        record_magic=False,
        save_core=False,
        record_file_maps=False,  # pylint: disable=arguments-differ
        crash_addr=None,
        trace_bb_addr=None,
        taint=None,
        **kwargs,
    ):  # pylint:disable=arguments-differ
        with self._target_mk_tmpdir() as tmpdir:
            tmp_prefix = mktemp(dir="/tmp", prefix="tracer-")
            target_trace_filename = tmp_prefix + ".trace" if record_trace else None
            target_magic_filename = tmp_prefix + ".magic" if record_magic else None
            local_core_filename = tmp_prefix + ".core" if save_core else None
            local_halfway_core_filename = (
                tmp_prefix + f".halfway_{hex(crash_addr[0])}_{crash_addr[1]}.core"
                if crash_addr
                else None
            )

            target_cmd = self._build_command(
                trace_filename=target_trace_filename,
                magic_filename=target_magic_filename,
                coredump_dir=tmpdir,
                crash_addr=crash_addr,
                start_trace_addr=trace_bb_addr,
                taint=taint,
            )

            l.debug("launch QEMU with command: %s", " ".join(target_cmd))
            r = QemuTraceResult()

            try:
                with self.target.flight_context(
                    target_cmd, timeout=self.timeout, result=r, **kwargs
                ) as flight:
                    yield flight
            except TimeoutExpired:
                r.timed_out = True
            else:
                r.timed_out = False
                r.returncode = flight.process.returncode

                # did a crash occur?
                if r.returncode in [139, -11]:
                    r.crashed = True
                    r.signal = SIGSEGV
                elif r.returncode == [132, -9]:
                    r.crashed = True
                    r.signal = SIGILL

            l.debug(
                "Qemu tracer returned with code=%s timed_out=%s crashed=%s signal=%s",
                r.returncode,
                r.timed_out,
                r.crashed,
                r.signal,
            )

            if local_core_filename or crash_addr:
                # choose the correct core dump to retrieve
                with self._local_mk_tmpdir() as local_tmpdir:
                    self.target.retrieve_into(tmpdir, local_tmpdir)
                    target_cores = glob(join(local_tmpdir, "*", "qemu_*.core"))
                    tmp_crash_core_path = None
                    tmp_halfway_core_path = None

                    for x in target_cores:
                        if "crash" in x.rsplit("_")[-1]:
                            tmp_crash_core_path = x
                        if "coreaddr" in x.rsplit("_")[-1]:
                            tmp_halfway_core_path = x

                    if tmp_crash_core_path is None and len(target_cores) == 1:
                        tmp_crash_core_path = target_cores[0]

                    # sanity check core dumps
                    if save_core and not tmp_crash_core_path:
                        raise QEMUTracerError(
                            "the target didn't crash inside qemu or no corefile was created!"
                            + "Make sure you launch it correctly!\n"
                            + "command: %s" % " ".join(target_cmd)
                        )
                    if crash_addr and not tmp_halfway_core_path:
                        raise QEMUTracerError(
                            "the target didn't generate a halfway core file!"
                            + "command: %s" % " ".join(target_cmd)
                        )

                    if local_core_filename and tmp_crash_core_path:
                        move(tmp_crash_core_path, local_core_filename)
                    if local_halfway_core_filename and tmp_halfway_core_path:
                        move(tmp_halfway_core_path, local_halfway_core_filename)
                    r.core_path = local_core_filename
                    r.halfway_core_path = local_halfway_core_filename

            if target_trace_filename:
                trace = self.target.retrieve_contents(target_trace_filename)
                trace_iter = self.line_iter(trace)

                # Find where qemu loaded the binary. Primarily for PIE
                try:
                    # the image base is the first mapped address in the page dump following the log line 'guest_base'
                    for t in trace_iter:
                        if t.startswith(b"guest_base"):
                            # iterate to the appropriate line
                            next(trace_iter)
                            next(trace_iter)
                            t = next(trace_iter)
                            # parse out the first line
                            r.image_base = int(t.split(b"-")[0], 16)
                            break

                    r.base_address = int(
                        next(
                            t.split()[1]
                            for t in trace_iter
                            if t.startswith(b"start_code")
                        ),
                        16,
                    )  # pylint:disable=stop-iteration-return

                    # for a dynamically linked binary, the entry point is in the runtime linker
                    # in this case it can be useful to keep track of the entry point
                    r.entry_point = int(
                        next(
                            t.split()[1] for t in trace_iter if t.startswith(b"entry")
                        ),
                        16,
                    )
                except StopIteration as e:
                    raise QEMUTracerError(
                        "The trace does not include any data. Did you forget to chmod +x the binary?"
                    ) from e

                # record the trace
                _trace_re = (
                    _trace_old_re if self.target.target_os == "cgc" else _trace_new_re
                )
                r.trace = [
                    int(_trace_re.match(t).group("addr"), 16)
                    for t in trace_iter
                    if t.startswith(b"Trace ")
                ]

                endings = trace.rsplit(b"\n", 3)[1:3]

                if r.crashed:
                    # grab the taint_fd
                    if not endings[0].startswith(
                        b"qemu: last read marker was read through fd:"
                    ):
                        l.error(
                            "Unexpected status line from qemu tracer. Cannot get the last read marker to set taint_fd. "
                            "Please make sure you are using the latest afl-qemu-trace."
                        )
                    else:
                        r.taint_fd = int(search(br"\[(\d+)\]", endings[0]).group(1))
                        l.debug("Detected the tainted fd to be %s", r.taint_fd)
                    # grab the faulting address
                    lastline = endings[-1]
                    if (
                        lastline.startswith(b"Trace")
                        or lastline.find(b"Segmentation") == -1
                    ):
                        l.warning(
                            "Trace return code was less than zero, but the last line of the trace does not"
                            "contain the uncaught exception error from qemu."
                            "If using an older version of shellphish_qemu try using 'ulimit -Sc 0' or "
                            "updating to a newer version of shellphish_qemu."
                        )
                    r.crash_address = int(lastline.split(b"[")[1].split(b"]")[0], 16)
                    l.debug("Detected the crashing address at %s", hex(r.crash_address))

                l.debug("Trace consists of %d basic blocks", len(r.trace))

                if record_file_maps:
                    strace_lines = filter_strace_output(
                        [line.decode("utf-8") for line in self.line_iter(trace)]
                    )
                    r.mapped_files = get_file_maps(strace_lines)

                # remove the trace file on the target
                self.target.remove_path(target_trace_filename)

            if target_magic_filename:
                r.magic_contents = self.target.retrieve_contents(target_magic_filename)
                if len(r.magic_contents) != 0x1000:
                    raise QEMUTracerError(
                        "Magic content read from QEMU improper size, should be a page in length"
                    )

                # remove the magic file on the target
                self.target.remove_path(target_magic_filename)

    @staticmethod
    def qemu_variant(target_os, target_arch, record_trace):
        """
        Need to know if we're tracking or not, specifically for what cgc qemu to use.
        """

        qemu_variant = f"afl-qemu-trace-{target_arch}"

        return qemu_variant

    def _build_command(
        self,
        trace_filename=None,
        magic_filename=None,
        coredump_dir=None,
        report_bad_args=None,
        crash_addr=None,
        start_trace_addr=None,
        taint=None,
    ):
        """
        Here, we build the tracing command.
        """

        #
        # First, the implant invocation
        #

        qemu_variant = self.qemu_variant(
            self.target.target_os, self.target.target_arch, trace_filename is not None
        )
        qemu_path = join(self.target.tmpwd, "afl_qemu_trace", qemu_variant)
        fire_path = join(self.target.tmpwd, "afl_qemu_trace", "fire")
        cmd_args = [fire_path, qemu_path]

        flags = "nochain,exec,page,strace"
        cmd_args += ["-d", flags, "-D", trace_filename]

        if self.seed is not None:
            cmd_args.append("-seed")
            cmd_args.append(str(self.seed))

        if "LD_BIND_NOW=1" not in self.target.target_env:
            cmd_args += ["-E", "LD_BIND_NOW=1"]

        if self.ld_preload:
            cmd_args += ["-E", "LD_PRELOAD=" + self.ld_preload]

        if self.library_path and not self.ld_linux:
            cmd_args += ["-E", "LD_LIBRARY_PATH=" + self.library_path]

        if self.ld_linux:
            cmd_args += [self.ld_linux]
            if self.library_path:
                cmd_args += ["--library-path", self.library_path]

        # Now, we add the program arguments.
        cmd_args += ["--"]  # separate QEMU arguments and target arguments
        cmd_args += self.target.target_args

        return cmd_args
