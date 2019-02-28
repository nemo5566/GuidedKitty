"""



"""
from kitty.model.low_level.field import BaseField
from kitty.model.low_level.encoder import BitsEncoder, ENC_BITS_DEFAULT
from kitty.core import kassert, KittyException, khash
from kitty.model.low_level.encoder import strToBytes
from bitstring import Bits, BitArray


class DetField(BaseField):
    """
    """
    _encoder_type_ = BitsEncoder

    def __init__(self, value, fuzzable=True, arith_max=35, name=None):
        """
        :param value: value to mutate (str or bytes)
        :param fuzzable: is field fuzzable (default: True)
        :param name: name of the object (default: None)
        :param arith_max:Maximum offset for integer addition / subtraction stages

        :raises: ``KittyException`` if num_bits is bigger than the value length in bits
        :raises: ``KittyException`` if num_bits is not positive
        """

        kassert.is_of_types(value, (bytes, bytearray, str))
        value = strToBytes(value)
        if len(value) * 8 < 32:
            raise KittyException('len of value in bits(%d) < num_bits(%d)' % (len(value) * 8, 32))
        self._num_bits = 1
        super(DetField, self).__init__(value=Bits(bytes=value), encoder=ENC_BITS_DEFAULT, fuzzable=fuzzable, name=name)
        self._arith_max = arith_max
        self._data_len_bytes = len(value)
        self._data_len_bits = self._data_len_bytes * 8
        self._bitflip_1_1_num_mutations = self._data_len_bits
        self._bitflip_2_1_num_mutations = self._data_len_bits - 1
        self._bitflip_4_1_num_mutations = self._data_len_bits - 3
        self._bitflip_8_8_num_mutations = self._data_len_bytes
        self._bitflip_16_8_num_mutations = self._data_len_bytes - 1
        self._bitflip_32_8_num_mutations = self._data_len_bytes - 3
        self._arith_8_8_num_mutations = self._data_len_bytes * 2 * self._arith_max
        self._arith_16_8_num_mutations = (self._data_len_bytes - 1) * 4 * self._arith_max
        self._arith_32_8_num_mutations = (self._data_len_bytes - 3) * 4 * self._arith_max
        self._num_mutations = self._data_len_bits * 3 - 4 + self._data_len_bytes * 3 - 4 + (
                    10 * self._data_len_bytes - 16) * self._arith_max
        self._strategy = ["bitflip_1_1", "bitflip_2_1", "bitflip_4_1", "bitflip_8_8", "bitflip_16_8", "bitflip_32_8",
                          "arith_8_8", "arith_16_8", "arith_32_8"]
        self._strategy_idx = 0
        self._base_number = 0
        self._current_offset = 0
        self._arith_tmp = 1

    def _start_end(self):
        self._current_offset = self._current_index - self._base_number
        if self._strategy_idx < 4:
            start_idx = self._current_offset
        elif 4 <= self._strategy_idx < 6:
            start_idx = self._current_offset * 8
        elif self._strategy_idx == 6:
            start_idx = (self._current_offset % self._data_len_bytes) * 8
        elif self._strategy_idx == 7:
            start_idx = (self._current_offset % (self._data_len_bytes - 1)) * 8
        elif self._strategy_idx == 8:
            start_idx = (self._current_offset % (self._data_len_bytes - 3)) * 8
        end_idx = start_idx + self._num_bits
        return start_idx, end_idx

    def _get_strategy_idx(self):
        if self._current_index == self._bitflip_1_1_num_mutations - 1:
            self._strategy_idx = 1
            self._base_number += self._bitflip_1_1_num_mutations
        elif self._current_index == self._bitflip_1_1_num_mutations + self._bitflip_2_1_num_mutations - 1:
            self._strategy_idx = 2
            self._base_number += self._bitflip_2_1_num_mutations
        elif self._current_index == self._bitflip_1_1_num_mutations + self._bitflip_2_1_num_mutations + self._bitflip_4_1_num_mutations - 1:
            self._strategy_idx = 3
            self._base_number += self._bitflip_4_1_num_mutations
        elif self._current_index == self._bitflip_1_1_num_mutations + self._bitflip_2_1_num_mutations + self._bitflip_4_1_num_mutations + self._bitflip_8_8_num_mutations - 1:
            self._strategy_idx = 4
            self._base_number += self._bitflip_8_8_num_mutations
        elif self._current_index == self._bitflip_1_1_num_mutations + self._bitflip_2_1_num_mutations + self._bitflip_4_1_num_mutations + self._bitflip_8_8_num_mutations + self._bitflip_16_8_num_mutations - 1:
            self._strategy_idx = 5
            self._base_number += self._bitflip_16_8_num_mutations
        elif self._current_index == self._bitflip_1_1_num_mutations + self._bitflip_2_1_num_mutations + self._bitflip_4_1_num_mutations + self._bitflip_8_8_num_mutations + self._bitflip_16_8_num_mutations + self._bitflip_32_8_num_mutations - 1:
            self._strategy_idx = 6
            self._base_number += self._bitflip_32_8_num_mutations
        elif self._current_index == self._bitflip_1_1_num_mutations + self._bitflip_2_1_num_mutations + self._bitflip_4_1_num_mutations + self._bitflip_8_8_num_mutations + self._bitflip_16_8_num_mutations + self._bitflip_32_8_num_mutations + self._arith_8_8_num_mutations - 1:
            self._strategy_idx = 7
            self._base_number += self._arith_8_8_num_mutations
        elif self._current_index == self._bitflip_1_1_num_mutations + self._bitflip_2_1_num_mutations + self._bitflip_4_1_num_mutations + self._bitflip_8_8_num_mutations + self._bitflip_16_8_num_mutations + self._bitflip_32_8_num_mutations + self._arith_8_8_num_mutations + self._arith_16_8_num_mutations - 1:
            self._strategy_idx = 8
            self._base_number += self._arith_16_8_num_mutations
        # elif self._current_index == self._base_number + self._arith_32_8_num_mutations -1:
        #     self._strategy_idx += 1
        #     self._base_number += self._arith_32_8_num_mutations
        return

    def _mutate(self):
        print self._strategy_idx, self._current_offset, self._current_index
        method_name = "_" + self._strategy[self._strategy_idx]
        method = getattr(self, method_name)
        method()
        self._get_strategy_idx()

    def get_info(self):
        info = super(DetField, self).get_info()
        # info['strategy'] = 'bit flip'
        # info['bits to flip'] = self._num_bits
        # start, end = self._start_end()
        # info['start bit'] = start
        # info['end bit'] = end
        return info

    def hash(self):
        hashed = super(DetField, self).hash()
        return khash(hashed, self._num_bits)

    def _bitflip_1_1(self):
        self._num_bits = 1
        new_val = BitArray(self._default_value).copy()
        start, end = self._start_end()
        new_val.invert(range(start, end))
        self.set_current_value(Bits(new_val))

    def _bitflip_2_1(self):
        self._num_bits = 2
        new_val = BitArray(self._default_value).copy()
        start, end = self._start_end()
        new_val.invert(range(start, end))
        self.set_current_value(Bits(new_val))

    def _bitflip_4_1(self):
        self._num_bits = 4
        new_val = BitArray(self._default_value).copy()
        start, end = self._start_end()
        new_val.invert(range(start, end))
        self.set_current_value(Bits(new_val))

    def _bitflip_8_8(self):
        self._num_bits = 8
        new_val = BitArray(self._default_value).copy()
        start, end = self._start_end()
        new_val.invert(range(start, end))
        self.set_current_value(Bits(new_val))

    def _bitflip_16_8(self):
        self._num_bits = 16
        new_val = BitArray(self._default_value).copy()
        start, end = self._start_end()
        new_val.invert(range(start, end))
        self.set_current_value(Bits(new_val))

    def _bitflip_32_8(self):
        self._num_bits = 32
        new_val = BitArray(self._default_value).copy()
        start, end = self._start_end()
        new_val.invert(range(start, end))
        self.set_current_value(Bits(new_val))

    def _arith_8_8(self):
        self._num_bits = 8
        self._arith_tmp = self._current_offset//self._data_len_bytes + 1
        start, end = self._start_end()
        new_val = BitArray(self._default_value).copy()
        tmp_val = new_val[start: end].uint
        if self._arith_tmp < self._arith_max:
            tmp_val += self._arith_tmp
        else:
            self._arith_tmp = self._arith_tmp % self._arith_max
            tmp_val -= self._arith_tmp
        tmp_bit = Bits(int=tmp_val, length=self._num_bits)
        new_val.overwrite(tmp_bit, start)
        self.set_current_value(Bits(new_val))

    def _arith_16_8(self):
        self._num_bits = 16
        self._arith_tmp = self._current_offset//(self._data_len_bytes-1) + 1
        start, end = self._start_end()
        new_val = BitArray(self._default_value).copy()
        tmp_val = new_val[start: end]
        if self._arith_tmp in range(0, self._arith_max):
            tmp_val = tmp_val.uint
            tmp_val += self._arith_tmp
        elif self._arith_tmp in range(self._arith_max, self._arith_max*2):
            tmp_val = tmp_val.uint
            self._arith_tmp = self._arith_tmp % self._arith_max
            tmp_val -= self._arith_tmp
        elif self._arith_tmp in range(self._arith_max*2, self._arith_max*3):
            tmp_val.byteswap(2)
            tmp_val = tmp_val.uint
            self._arith_tmp = self._arith_tmp % self._arith_max
            tmp_val += self._arith_tmp
        elif self._arith_tmp in range(self._arith_max*3, self._arith_max*4):
            tmp_val.byteswap(2)
            tmp_val = tmp_val.uint
            self._arith_tmp = self._arith_tmp % self._arith_max
            tmp_val -= self._arith_tmp
        print tmp_val
        tmp_bit = Bits(int=tmp_val, length=self._num_bits)
        new_val.overwrite(tmp_bit, start)
        self.set_current_value(Bits(new_val))

    def _arith_32_8(self):
        self._num_bits = 32
        self._arith_tmp = self._current_offset//(self._data_len_bytes-1) + 1
        start, end = self._start_end()
        new_val = BitArray(self._default_value).copy()
        tmp_val = new_val[start: end]
        if self._arith_tmp in range(0, self._arith_max):
            tmp_val = tmp_val.uint
            tmp_val += self._arith_tmp
        elif self._arith_tmp in range(self._arith_max, self._arith_max*2):
            tmp_val = tmp_val.uint
            self._arith_tmp = self._arith_tmp % self._arith_max
            tmp_val -= self._arith_tmp
        elif self._arith_tmp in range(self._arith_max*2, self._arith_max*3):
            tmp_val.byteswap(4)
            tmp_val = tmp_val.uint
            self._arith_tmp = self._arith_tmp % self._arith_max
            tmp_val += self._arith_tmp
        elif self._arith_tmp in range(self._arith_max*3, self._arith_max*4):
            tmp_val.byteswap(4)
            tmp_val = tmp_val.uint
            self._arith_tmp = self._arith_tmp % self._arith_max
            tmp_val -= self._arith_tmp
        tmp_bit = Bits(int=tmp_val, length=self._num_bits)
        new_val.overwrite(tmp_bit, start)
        self.set_current_value(Bits(new_val))
