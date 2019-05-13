
"""

"""

import struct
import sys
import os
import array
import bisect
import time
import traceback
from binascii import hexlify

from kitty.data.report import Report
from kitty.targets.base import BaseTarget

kMagic32SecondHalf = 0xFFFFFF32
kMagic64SecondHalf = 0xFFFFFF64
kMagicFirstHalf = 0xC0BFFFFF

MAP_SIZE = 65536

class GuidedTarget(BaseTarget):
    '''
    Target that does nothing. Weird, but sometimes it is required.
    '''

    def __init__(self, name, logger=None, expect_response=False, sancov_path=None):
        '''
        :param name: name of the target
        :param logger: logger for this object (default: None)
        '''
        super(GuidedTarget, self).__init__(name, logger)
        self.expect_response = False
        self.expect_response = expect_response
        self.send_failure = False
        self.receive_failure = False
        self.transmission_count = 0
        self.transmission_report = None
        self.sancov_path = sancov_path
        self.first_run = True


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
                dst_path = os.path.join(self.sancov_path,
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


    def get_cov_file(self):
        sancov_raw_name = None
        sancov_name = None
        sancov_file = None
        if os.path.exists(self.sancov_path):
            file_list = os.listdir(self.sancov_path)
            for i in file_list:
                if i.endswith(".sancov.raw"):
                    sancov_raw_name = i
                if i.endswith(".sancov"):
                    sancov_name = i
        if sancov_raw_name is None and sancov_name is None:
            assert sancov_raw_name and sancov_name, "[Error]Can't find sancov file!!!!"
        if sancov_raw_name is not None:
            sancov_raw_path = os.path.join(self.sancov_path, sancov_raw_name)
            sancov_map_path = sancov_raw_path[: -3] + "map"
            if not os.path.isfile(sancov_map_path):
                assert ("[Error]Can't find sancov map file!!!!")
            sancov_file = self.sancov_analyse(sancov_raw_path, sancov_map_path)
        if sancov_name is not None:
            sancov_file = os.path.join(self.sancov_path, sancov_name)
        return sancov_file


    def get_bit_map(self, file):
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
        return trace_bits

    def set_expect_response(self, expect_response):
        '''
        :param expect_response: should wait for response from the victim (default: False)
        '''
        self.expect_response = expect_response

    def _send_to_target(self, payload):
        self.not_implemented('send_to_target')

    def _receive_from_target(self):
        self.not_implemented('receive_from_target')

    def pre_test(self, test_num):
        '''
        Called before each test

        :param test_num: the test number
        '''
        super(GuidedTarget, self).pre_test(test_num)
        self.send_failure = False
        self.receive_failure = False
        self.transmission_count = 0

    def transmit(self, payload):
        '''
        Transmit single payload, and receive response, if expected.
        The actual implementation of the send/receive should be in
        ``_send_to_target`` and ``_receive_from_target``.

        :type payload: str
        :param payload: payload to send
        :rtype: str
        :return: the response (if received) and trace_bits
        '''
        response = None
        trans_report_name = 'transmission_0x%04x' % self.transmission_count
        trans_report = Report(trans_report_name)
        self.transmission_report = trans_report
        self.report.add(trans_report_name, trans_report)
        try:
            trans_report.add('request (hex)', hexlify(payload).decode())
            trans_report.add('request (raw)', '%s' % payload)
            trans_report.add('request length', len(payload))
            trans_report.add('request time', time.time())

            request = hexlify(payload).decode()
            request = request if len(request) < 100 else (request[:100] + ' ...')
            self.logger.info('request(%d): %s' % (len(payload), request))
            self._send_to_target(payload)
            trans_report.success()

            if self.expect_response:
                try:
                    response = self._receive_from_target()
                    trans_report.add('response time', time.time())
                    trans_report.add('response (hex)', hexlify(response).decode())
                    trans_report.add('response (raw)', '%s' % response)
                    trans_report.add('response length', len(response))
                    printed_response = hexlify(response).decode()
                    printed_response = printed_response if len(printed_response) < 100 else (printed_response[:100] + ' ...')
                    self.logger.info('response(%d): %s' % (len(response), printed_response))
                except Exception as ex2:
                    trans_report.failed('failed to receive response: %s' % ex2)
                    trans_report.add('traceback', traceback.format_exc())
                    self.logger.error('target.transmit - failure in receive (exception: %s)' % ex2)
                    self.logger.error(traceback.format_exc())
                    self.receive_failure = True
            else:
                response = ''
        except Exception as ex1:
            trans_report.failed('failed to send payload: %s' % ex1)
            trans_report.add('traceback', traceback.format_exc())
            self.logger.error('target.transmit - failure in send (exception: %s)' % ex1)
            self.logger.error(traceback.format_exc())
            self.send_failure = True
        self.transmission_count += 1
        if self.first_run:
            time.sleep(0.5)
            self.first_run = False
        sancov_file = self.get_cov_file()
        trace_bits = self.get_bit_map(sancov_file)
        return response, trace_bits

    def post_test(self, test_num):
        '''
        Called after each test

        :param test_num: the test number
        '''
        super(GuidedTarget, self).post_test(test_num)
        if self.send_failure:
            self.report.failed('send failure')
        elif self.expect_response and self.receive_failure:
            self.report.failed('receive failure')
