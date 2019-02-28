"""

"""

from struct import pack
from common import BaseTestCase, metaTest
from kitty.core import KittyException
from kitty.model.low_level.guided_low_field import DetField
from kitty.model.low_level.encoder import strToBytes

class DetFieldTests(BaseTestCase):

    def setUp(self):
        super(DetField, self).setup(DetField)

    def get_field(self, value=b'\x12\x34\x12\x34\x12\x34\x12\x34\x12\x34', arith_max=32):
        return DetField(value=value, arith_max=arith_max)

    def _testBase(self, value, num_bits_to_flip, expected_mutations):
        len_in_bits = len(value) * 8
        uut = self.get_field(value=value, num_bits=num_bits_to_flip)
        self.assertEqual(uut.num_mutations(), len_in_bits - num_bits_to_flip + 1)
        mutations = map(lambda x: x.tobytes(), self.get_all_mutations(uut))
        self.assertEqual(set(mutations), set(expected_mutations))
