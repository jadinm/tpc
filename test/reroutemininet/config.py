import json
import json
import os
import shlex
import subprocess
import time

from ipmininet.host.config.base import HostDaemon
from srnmininet.config.config import SRNDaemon, srn_template_lookup
from srnmininet.srnrouter import mkdir_p

__TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates')
srn_template_lookup.directories.append(__TEMPLATES_DIR)


class SRLocalCtrl(SRNDaemon):
    """The class representing the sr-localctrl daemon
    used on the host to fill eBPF map and reading the database"""

    NAME = 'sr-localctrl'
    KILL_PATTERNS = (NAME,)
    PRIO = 1  # If other daemons want to use it
    BPFTOOL = "bpftool"
    N_RTO_CHANGER_EBPF_PROGRAM = os.path.join(os.environ["TPC_EBPF"], "ebpf_n_rto_changer.o")
    TIMEOUT_CHANGER_EBPF_PROGRAM = os.path.join(os.environ["TPC_EBPF"], "ebpf_timeout_changer.o")
    EXP3_LOWEST_DELAY_EBPF_PROGRAM = os.path.join(os.environ["TPC_EBPF"], "ebpf_exp3_lowest_delay.o")
    EXP3_LOWEST_COMPLETION_EBPF_PROGRAM = os.path.join(os.environ["TPC_EBPF"], "ebpf_exp3_lowest_completion.o")
    REVERSE_SRH_PROGRAM = os.path.join(os.environ["TPC_EBPF"], "ebpf_reverse_srh.o")
    USE_SECOND_PROGRAM = os.path.join(os.environ["TPC_EBPF"], "ebpf_use_second_path.o")
    TRACEROUTE = os.path.join(os.environ["TPC_EBPF"], "ebpf_traceroute.o")

    def __init__(self, *args, template_lookup=srn_template_lookup, **kwargs):
        super().__init__(*args, template_lookup=template_lookup, **kwargs)
        self.files.append(
            self.ebpf_load_path(self._node.name, self.options.long_ebpf_program))
        self.files.append(self.map_path("dest_map_fd", self.options.long_ebpf_program))
        self.files.append(self.map_path("short_dest_map_fd",
                                        self.options.short_ebpf_program))
        os.makedirs(self._node.cwd, exist_ok=True)
        self.attached = {self.options.short_ebpf_program: False,
                         self.options.long_ebpf_program: False}
        self.stat_map_id = -1
        self.dest_map_id = -1
        self.short_dest_map_id = -1
        self.short_stat_map_id = -1
        self.reverse_stat_map_id = -1

    @classmethod
    def all_programs(cls):
        return [cls.N_RTO_CHANGER_EBPF_PROGRAM, cls.TIMEOUT_CHANGER_EBPF_PROGRAM,
                cls.EXP3_LOWEST_DELAY_EBPF_PROGRAM, cls.EXP3_LOWEST_COMPLETION_EBPF_PROGRAM, cls.REVERSE_SRH_PROGRAM,
                cls.USE_SECOND_PROGRAM, cls.TRACEROUTE]

    def set_defaults(self, defaults):
        super().set_defaults(defaults)
        # defaults.loglevel = self.DEBUG  # TODO Remove
        defaults.bpftool = self.BPFTOOL
        defaults.long_ebpf_program = self.N_RTO_CHANGER_EBPF_PROGRAM
        defaults.short_ebpf_program = self.EXP3_LOWEST_DELAY_EBPF_PROGRAM
        defaults.reverse_srh_ebpf_program = self.REVERSE_SRH_PROGRAM

    def cgroup(self, program):
        ext = os.path.basename(program).replace(".o", "").replace("ebpf_", "")
        return "/sys/fs/cgroup/unified/{node}_{daemon}_{ext}.slice/".format(
            node=self._node.name, daemon=self.NAME, ext=ext)

    @classmethod
    def ebpf_load_path(cls, node_name, program):
        return "/sys/fs/bpf/{node}_{daemon}_{program}" \
            .format(node=node_name, daemon=cls.NAME,
                    program=os.path.basename(program).split(".")[0])

    def map_path(self, map_name, program):
        return self.ebpf_load_path(self._node.name, program) + "_" + map_name

    def get_map_id(self, program):
        ebpf_load_path = self.ebpf_load_path(self._node.name, program)
        cmd = "{bpftool} prog -j show pinned {ebpf_load_path}" \
            .format(bpftool=self.options.bpftool,
                    ebpf_load_path=ebpf_load_path)
        print(cmd)
        out = subprocess.check_output(shlex.split(cmd)).decode("utf-8")
        try:
            map_ids = json.loads(out)["map_ids"]
        except (json.JSONDecodeError, KeyError) as e:
            print("Cannot get the map ids of %s" % ebpf_load_path)
            raise e

        if len(map_ids) == 0:
            raise ValueError("Cannot find the maps of %s" % ebpf_load_path)
        return map_ids

    def pin_maps(self):

        map_ids = []
        map_ids.extend(self.get_map_id(self.options.long_ebpf_program))
        print("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
        print(self.options.long_ebpf_program)
        print(self.options.short_ebpf_program)
        print(self.options.reverse_srh_ebpf_program)
        print("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
        map_ids.extend(self.get_map_id(self.options.short_ebpf_program))

        # Pin maps to fds
        for map_id in map_ids:

            cmd = "{bpftool} map -j show id {map_id}" \
                .format(bpftool=self.options.bpftool, map_id=map_id)
            print(cmd)
            out = subprocess.check_output(shlex.split(cmd)).decode("utf-8")
            try:
                map_name = json.loads(out)["name"]
            except (json.JSONDecodeError, KeyError) as e:
                print("Cannot get the map ids")
                raise e

            # If the map is the destination map, pin it
            # The other map is an internal map for the eBPF program
            if map_name == "dest_map":
                cmd = "{bpftool} map pin id {dest_map_id} {map_path}" \
                    .format(bpftool=self.options.bpftool,
                            dest_map_id=map_id,
                            map_path=self.map_path("dest_map",
                                                   self.options.long_ebpf_program))
                print(cmd)
                subprocess.check_call(shlex.split(cmd))
                self.dest_map_id = map_id
            if map_name == "short_dest_map":
                cmd = "{bpftool} map pin id {dest_map_id} {map_path}" \
                    .format(bpftool=self.options.bpftool,
                            dest_map_id=map_id,
                            map_path=self.map_path("short_dest_map",
                                                   self.options.short_ebpf_program))
                print(cmd)
                subprocess.check_call(shlex.split(cmd))
                self.short_dest_map_id = map_id
            if map_name == "stat_map":
                self.stat_map_id = map_id
            if map_name == "short_stat_map":
                self.short_stat_map_id = map_id
            if map_name == "reverse_stat_map":
                self.reverse_stat_map_id = map_id
        if self.dest_map_id == -1:
            raise ValueError("Cannot pin the dest_map of program %s"
                             % self.ebpf_load_path(self._node.name,
                                                   self.options.long_ebpf_program))
        if self.short_dest_map_id == -1:
            raise ValueError("Cannot pin the dest_map of program %s"
                             % self.ebpf_load_path(self._node.name,
                                                   self.options.short_ebpf_program))
        return self.dest_map_id, self.short_dest_map_id

    def render(self, cfg, **kwargs):

        # Extract IDs

        time.sleep(1)

        dest_map_id, short_dest_map_id = self.pin_maps()

        # Create cgroup
        for program in [self.options.long_ebpf_program, self.options.short_ebpf_program,
                        self.options.reverse_srh_ebpf_program]:
            mkdir_p(self.cgroup(program))

            ebpf_load_path = self.ebpf_load_path(self._node.name,
                                                 program)
            cmd = "{bpftool} cgroup attach {cgroup} sock_ops" \
                  " pinned {ebpf_load_path} multi" \
                .format(bpftool=self.options.bpftool,
                        cgroup=self.cgroup(program),
                        ebpf_load_path=ebpf_load_path)
            print(cmd)
            subprocess.check_call(shlex.split(cmd))

            self.attached[program] = True

        # Fill config template

        cfg[self.NAME].dest_map_id = dest_map_id
        cfg[self.NAME].short_dest_map_id = short_dest_map_id
        cfg_content = super().render(cfg, **kwargs)

        return cfg_content

    def cleanup(self):
        detach_cmd = "{bpftool} cgroup detach {cgroup} sock_ops" \
                     " pinned {ebpf_load_path} multi"
        for program in [self.options.long_ebpf_program, self.options.short_ebpf_program,
                        self.options.reverse_srh_ebpf_program]:
            if self.attached[program]:
                ebpf_load_path = self.ebpf_load_path(self._node.name, program)
                cmd = detach_cmd.format(bpftool=self.options.bpftool,
                                        cgroup=self.cgroup(program),
                                        ebpf_load_path=ebpf_load_path)
                print(detach_cmd)
                subprocess.check_call(shlex.split(cmd))

        super().cleanup()


class Lighttpd(HostDaemon):
    NAME = 'lighttpd'
    # DEPENDS = (SRLocalCtrl,)  # Need to have eBPF loaded before starting
    KILL_PATTERNS = (NAME,)

    def __init__(self, *args, template_lookup=srn_template_lookup, **kwargs):
        super().__init__(*args, template_lookup=template_lookup, **kwargs)

    @property
    def startup_line(self):
        time.sleep(1)
        s = "{ebpf} {program} {name} -D -f {conf}" \
            .format(ebpf="ebpf" if self.options.ebpf else "", name=self.NAME,
                    conf=self.cfg_filename,
                    program=self.options.ebpf
                    if self.options.ebpf else "")
        print(s)
        return s

    @property
    def dry_run(self):
        return "{name} -tt -f {conf}".format(name=self.NAME,
                                             conf=self.cfg_filename)

    def build(self):
        cfg = super().build()
        cfg.web_dir = self.options.web_dir
        cfg.pid_file = self._file(suffix='pid')
        cfg.port = self.options.port
        return cfg

    def render(self, cfg, **kwargs):
        cfg_content = super().render(cfg, **kwargs)
        # Create the big file
        path = os.path.join(self._node.cwd, "mock_file")
        os.makedirs(self._node.cwd, exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w") as fileobj:
                fileobj.write("0" * 10 ** 7)
            self.files.append(path)
        try:
            ctrl = self._node.nconfig.daemon(SRLocalCtrl)
        except KeyError:
            ctrl = None
        self.options.ebpf = ctrl.options.short_ebpf_program if ctrl else None

        return cfg_content

    def set_defaults(self, defaults):
        """
        :param port: The port on which the daemon listens for HTTP requests
        :param web_dir: The directory of files that can be queried
        :param ebpf: ebpf program to get attached to
        """
        defaults.port = 8080
        defaults.web_dir = self._node.cwd
        super().set_defaults(defaults)

    def has_started(self, *args):
        # Try to connect to the server
        _, _, ret = self._node.pexec("nc -z ::1 {port}"
                                     .format(port=self.options.port))
        return ret == 0
