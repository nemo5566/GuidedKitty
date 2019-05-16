# -*- coding:utf-8 -*-
# !/usr/bin/env python 2.7

import array
import bisect
import os
import struct
import sys
import array

import guider

kMagic32SecondHalf = 0xFFFFFF32
kMagic64SecondHalf = 0xFFFFFF64
kMagicFirstHalf = 0xC0BFFFFF

LOG_NAME = "SANCOV_LOG"
SANCOV_OUT_DIR = "coverage/SANCOV_OUT"
SANCOV_TOTAL = "total"
SANCOV_TOTAL_FILENAME = "total_coverage"

MAP_SIZE = 65536


class Guider(guider.Guider):

    def __init__(self, mode="fuzz"):

        self.logger = "."
        self.out_dir = "."
        self.process_name = "2-4cov.out"
        guider.Guider.__init__(self, self.process_name)

        self.mode = mode
        self.SANCOV_OUT_DIR = SANCOV_OUT_DIR
        """
        if self.mode == "trim":
            self.SANCOV_OUT_DIR = "SANCOV_OUT"
        """

        # feedback info
        self.total_cov = 0
        self.cov_total = 0
        self.coverage = 0
        self.interesting = 0

    def _check_bits(self, bits):
        if bits != 32 and bits != 64:
            raise Exception("Wrong bitness: %d" % bits)

    def _magic_for_bits(self, bits):
        self._check_bits(bits)
        if sys.byteorder == 'little':
            return [kMagic64SecondHalf if bits == 64 else kMagic32SecondHalf, kMagicFirstHalf]
        else:
            return [kMagicFirstHalf, kMagic64SecondHalf if bits == 64 else kMagic32SecondHalf]

    def _type_code_for_struct(self, bits):
        self._check_bits(bits)
        return 'Q' if bits == 64 else 'I'

    def sancov_analyse(self, raw, map):
        mem_map = list()
        with open(map, mode="rt") as f_map:
            # self.logger.debug("%s: reading map %s" % (sancov, map))
            bits = int(f_map.readline())
            if bits != 32 and bits != 64:
                raise Exception('Wrong bits size in the map')
            for line in f_map:
                parts = line.rstrip().split()
                mem_map.append((int(parts[0], 16), int(parts[1], 16), int(parts[2], 16), ' '.join(parts[3:])))
        f_map.close()
        mem_map.sort(key=lambda m: m[0])
        mem_map_keys = [m[0] for m in mem_map]

        with open(raw, mode="rb") as f:
            # self.logger.debug("%s: unpacking %s" % (sancov, raw))
            f.seek(0, 2)
            size = f.tell()
            f.seek(0, 0)
            pcs = struct.unpack_from(self._type_code_for_struct(bits) * (size * 8 / bits), f.read(size))
            mem_map_pcs = [[] for i in range(0, len(mem_map))]
            for pc in pcs:
                if pc == 0:
                    continue
                map_idx = bisect.bisect(mem_map_keys, pc) - 1
                (start, end, base, module_path) = mem_map[map_idx]

                assert pc >= start
                if pc >= end:
                    # self.logger.debug("warning: %s: pc %x outside of any known mapping" % (sancov, pc))
                    continue
                mem_map_pcs[map_idx].append(pc - base)

            for ((start, end, base, module_path), pc_list) in zip(mem_map, mem_map_pcs):
                if len(pc_list) == 0: continue
                assert raw.endswith('.sancov.raw')
                dst_path = os.path.join(self.out_dir, self.SANCOV_OUT_DIR,
                                        module_path + '.' + os.path.basename(raw)[:-4])
                # self.logger.debug("%s: writing %d PCs to %s" % (sancov, len(pc_list), dst_path))
                sorted_pc_list = sorted(pc_list)
                pc_buffer = struct.pack(self._type_code_for_struct(bits) * len(pc_list), *sorted_pc_list)
                with open(dst_path, 'ab+') as f2:
                    f2.write(array.array('I', self._magic_for_bits(bits)).tostring())
                    f2.seek(0, 2)
                    f2.write(pc_buffer)
                f2.close()
        f.close()
        return dst_path

    def _read_magic_return_bitness(self, f, path):
        magic_bytes = f.read(8)
        magic_words = struct.unpack('II', magic_bytes);
        bits = 0
        idx = 1 if sys.byteorder == 'little' else 0
        if magic_words[idx] == kMagicFirstHalf:
            if magic_words[1 - idx] == kMagic64SecondHalf:
                bits = 64
            elif magic_words[1 - idx] == kMagic32SecondHalf:
                bits = 32
        if bits == 0:
            raise Exception('Bad magic word in %s' % path)
        return bits

    def _parse_one_file(self, path):
        with open(path, mode="rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(0, 0)
            if size < 8:
                raise Exception('File %s is short (< 8 bytes)' % path)
            bits = self._read_magic_return_bitness(f, path)
            size -= 8
            s = struct.unpack_from(self._type_code_for_struct(bits) * (size * 8 / bits), f.read(size))

        f.close()
        # self.logger.debug("sancov: read %d %d-bit PCs from %s" % (size * 8 / bits, bits, path))
        return s

    def parse_sancov_file(self, file):
        new_edge = 0
        cov_total = 0
        s = self._parse_one_file(file)
        trace_bits = [0] * MAP_SIZE
        prev_loc = 0
        for cur_loc in s:
            cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
            cur_loc &= MAP_SIZE - 1
            trace_bits[prev_loc ^ cur_loc] += 1
            prev_loc = cur_loc >> 1

        target_dir = os.path.join(self.out_dir, self.SANCOV_OUT_DIR, SANCOV_TOTAL)
        if not os.path.exists(target_dir):
            self.logger.debug("[Error]can't find SANCOV_TOTAL DIR!!!")
            os.exit()
        target_file = os.path.join(target_dir, SANCOV_TOTAL_FILENAME)

        if os.path.isfile(target_file):
            f = open(target_file, 'r')
            total_bits = eval(f.read())
            f.close()
            i = 0
            while i < MAP_SIZE:
                if not total_bits[i] and trace_bits[i]:
                    new_edge += 1
                    total_bits[i] = total_bits[i] | trace_bits[i]
                if total_bits[i]:
                    cov_total += 1
                i += 1
            f = open(target_file, 'w')
            f.write(str(total_bits))
            f.close()
        else:
            i = 0
            while i < MAP_SIZE:
                if trace_bits[i]:
                    new_edge += 1
                i += 1
            cov_total = new_edge
            f = open(target_file, 'w')
            f.write(str(trace_bits))
            f.close()
        return new_edge, cov_total

    def trim(self, fileToMutate):

        fileToMutate.was_trimmed = 1

        sample = fileToMutate.filename
        f = open(sample, 'rb')
        old_data = f.read()
        f.close()

        try:
            from Monitors import ptrace_monitor
        except ImportError:
            import ptrace_monitor
        dbg = ptrace_monitor.Debugger(self.guider_args)
        dbg.run(sample)
        if dbg.new == True:
            import shutil
            shutil.copy(sample, os.path.join(self.out_dir, "crashes", dbg.hash))
        old_data_cov = self.get_cov_detail()

        TRIM_START_STEPS = 16
        TRIM_MIN_BYTES = 4
        TRIM_END_STEPS = 1024

        old_data_len = len(old_data)
        len_p2 = self._next_p2(old_data_len)
        remove_len = max(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES)
        continue_flag = True

        while remove_len >= max(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES) and continue_flag:
            remove_pos = remove_len
            while remove_pos < old_data_len and continue_flag:

                trim_avail = min(remove_len, old_data_len - remove_pos)
                new_data = ""
                if (remove_pos > 0):
                    new_data += old_data[0: remove_pos]
                if (trim_avail > 0 and remove_pos >= 0):
                    new_data += old_data[remove_pos + trim_avail:]
                f = open(sample, "wb")
                f.write(new_data)
                f.close()
                dbg.run(sample)
                if dbg.crashed and dbg.new:
                    import shutil
                    shutil.copy(sample, os.path.join(self.out_dir, "crashes", dbg.hash))
                    continue_flag = False
                new_data_cov = self.get_cov_detail()
                if new_data_cov == old_data_cov:
                    len_p2 = self._next_p2(len(new_data))
                    old_data = new_data
                    old_data_len = len(new_data)
                else:
                    remove_pos += remove_len
            remove_len >>= 1

        f = open(sample, "wb")
        f.write(old_data)
        f.close()

        return fileToMutate

    def get_cov_detail(self):
        """
        This function is a helper function of 'trim'
        """
        sancov_file_path = os.path.join(self.out_dir, self.SANCOV_OUT_DIR)
        sancov_raw_name = None
        sancov_name = None
        cov_bb_detail = list()
        if os.path.exists(sancov_file_path):
            file_list = os.listdir(sancov_file_path)
            for i in file_list:
                if i.endswith(".sancov.raw"):
                    sancov_raw_name = i
                if i.endswith(".sancov"):
                    sancov_name = i
        if sancov_raw_name is None and sancov_name is None:
            self.logger.error("[Error]Can't find sancov file in trim!!!!")
            return 0
        if sancov_raw_name is not None:
            sancov_raw_path = os.path.join(self.out_dir, self.SANCOV_OUT_DIR, sancov_raw_name)
            sancov_map_path = sancov_raw_path[: -3] + "map"
            if not os.path.isfile(sancov_map_path):
                self.logger.error("[Error]Can't find sancov map file in trim!!!!")
                return []
            file_name = self.sancov_analyse(sancov_raw_path, sancov_map_path)
            cov_bb_detail = self._parse_one_file(file_name)
        if sancov_name is not None:
            sancov_path = os.path.join(self.out_dir, self.SANCOV_OUT_DIR, sancov_name)
            cov_bb_detail = self._parse_one_file(sancov_path)
        return cov_bb_detail

    def run(self, sample):
        self.interesting = 0
        self.coverage = 0

        sancov_file_path = os.path.join(self.out_dir, self.SANCOV_OUT_DIR)
        sancov_raw_name = None
        sancov_name = None
        bitset_sancov_name = None
        new_edge = 0
        cov_total = 0

        if os.path.exists(sancov_file_path):
            file_list = os.listdir(sancov_file_path)
            for i in file_list:
                if i.endswith(".sancov.raw"):
                    sancov_raw_name = i
                if i.endswith(".sancov"):
                    sancov_name = i
        if sancov_raw_name is None and sancov_name is None:
            self.logger.error("[Error]Can't find sancov file!!!!")
            return 0
        if sancov_raw_name is not None:
            sancov_raw_path = os.path.join(self.out_dir, self.SANCOV_OUT_DIR, sancov_raw_name)
            sancov_map_path = sancov_raw_path[: -3] + "map"
            if not os.path.isfile(sancov_map_path):
                self.logger.error("[Error]Can't find sancov map file!!!!")
                return 0
            file_name = self.sancov_analyse(sancov_raw_path, sancov_map_path)
            new_edge, cov_total = self.parse_sancov_file(file_name)

        if sancov_name is not None:
            sancov_path = os.path.join(self.out_dir, self.SANCOV_OUT_DIR, sancov_name)
            new_edge, cov_total = self.parse_sancov_file(sancov_path)

        self.interesting = new_edge
        self.logger.info("new_edge: %d, cov_total: %d" % (new_edge, cov_total))

        if self.cov_total < cov_total:
            self.cov_total = cov_total
            self.coverage = "%.4f%%" % (float(self.cov_total) / MAP_SIZE * 100)
            self.logger.info("total_cov = %d, coverage = %s, \n" % (self.total_cov, self.coverage))
            self.log_information(os.path.join(self.out_dir, "coverage", "coverage.log"), MAP_SIZE, self.cov_total)

        return self.interesting


if __name__ == "__main__":
    sancovGuider = Guider("badcode_sancov")
    print sancovGuider.run()
    pass
    '''
    program = "c:\\Program Files\\Windows Journal\\Journal.exe"
    program = "c:\\Windows\\notepad.exe"
    sample = "sample.jnt"
    guider = PinGuider(program)
    guider.PIN_PATH = os.path.join("..", "Tools", "pin", "pin.exe")
    guider.PINTOOL = os.path.join("PinGuider", "pintools", "pin_guider.dll")
    guider.set_cmd_pintool(timeout=2000)
    guider.run(sample)
    guider.run(sample)
    '''
