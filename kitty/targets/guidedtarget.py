
"""

"""

from kitty.targets.server import ServerTarget
import struct
import sys

kMagic32SecondHalf = 0xFFFFFF32
kMagic64SecondHalf = 0xFFFFFF64
kMagicFirstHalf = 0xC0BFFFFF

MAP_SIZE = 65536

class GuidedTarget(ServerTarget):
    '''
    Target that does nothing. Weird, but sometimes it is required.
    '''

    def __init__(self, name, logger=None):
        '''
        :param name: name of the target
        :param logger: logger for this object (default: None)
        '''
        super(GuidedTarget, self).__init__(name, logger)
        self.expect_response = False

    def _send_to_target(self, payload):
        pass

    def _receive_from_target(self):
        return ''

    def post_test(self, test_num):
        pass

    def pre_test(self, test_num):
        pass

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