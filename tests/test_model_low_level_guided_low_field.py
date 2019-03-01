"""

"""

from struct import pack
from common import BaseTestCase, metaTest
from kitty.core import KittyException
from kitty.model.low_level.guided_low_field import DetField
from kitty.model.low_level.encoder import strToBytes


class DetFieldTests(BaseTestCase):

    def setUp(self):
        super(DetFieldTests, self).setUp(DetField)

    def get_field(self, value=b'\x00\x00\x00\x00', arith_max=32):
        return DetField(value=value, arith_max=arith_max)

    def _testBase(self, value,  expected_mutations):
        len_in_bits = len(value) * 8
        arith_max = 32
        uut = self.get_field(value=value)
        self.assertEqual(uut.num_mutations(),  len_in_bits * 3 - 4 + len(value)* 3 - 4 + (10 * len(value) - 16) * arith_max)
        mutations = map(lambda x: x.tobytes(), self.get_all_mutations(uut))
        self.assertEqual(set(mutations), set(expected_mutations))

    def testDetFieldOn32bits(self):
        expected_mutations = map(lambda i: strToBytes(chr(1 << i)), range(8))
        self._testBase(b'\x00\x00\x00\x00', expected_mutations)