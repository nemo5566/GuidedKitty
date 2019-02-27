"""



"""
from kitty.model.low_level.field import BaseField
from kitty.model.low_level.encoder import BitsEncoder, ENC_BITS_DEFAULT
from kitty.core import kassert, KittyException, khash
from kitty.model.low_level.encoder import strToBytes
from bitstring import Bits, BitArray


class DetField(BaseField):
    '''

    '''
    _encoder_type_ = BitsEncoder

    def __init__(self, value, fuzzable=True, arith_max=35, name=None):
        '''
        :param value: value to mutate (str or bytes)
        :param fuzzable: is field fuzzable (default: True)
        :param name: name of the object (default: None)
        :param arith_max:Maximum offset for integer addition / subtraction stages

        :raises: ``KittyException`` if num_bits is bigger than the value length in bits
        :raises: ``KittyException`` if num_bits is not positive
        '''
        kassert.is_of_types(value, (bytes, bytearray, str))
        value = strToBytes(value)
        self._num_bits = 1
        super(DetField, self).__init__(value=Bits(bytes=value), encoder=ENC_BITS_DEFAULT, fuzzable=fuzzable, name=name)
        self._data_len_bytes = len(value)
        self._data_len_bits = self._data_len_bytes * 8
        self._bitflip_1_1_num_mutations = self._data_len_bits
        self._bitflip_2_1_num_mutations = self._data_len_bits - 1
        self._bitflip_4_1_num_mutations = self._data_len_bits - 3
        self._bitflip_8_8_num_mutations = self._data_len_bytes
        self._bitflip_16_8_num_mutations = self._data_len_bytes - 1
        self._bitflip_32_8_num_mutations = self._data_len_bytes - 3
        self._arith_8_8_num_mutations = self._data_len_bytes*2*arith_max
        self._arith_16_8_num_mutations = (self._data_len_bytes - 1)*4*arith_max
        self._arith_32_8_num_mutations = (self._data_len_bytes - 3)*4*arith_max
        self._num_mutations = self._data_len_bits*3 - 4 + self._data_len_bytes*3 - 4 + (10*self._data_len_bytes - 16) * arith_max
        self._strategy = ["bitflip_1_1", "bitflip_2_1", "bitflip_4_1", "bitflip_8_8", "bitflip_16_8", "bitflip_32_8", "arith_8_8", "arith_16_8", "arith_32_8"]
        self._strategy_idx = 0
        self._base_number = 0
        self._current_offset = 0

    def _start_end(self):
        self._current_offset = self._current_index - self._base_number
        start_idx = self._current_offset
        end_idx = start_idx + self._num_bits
        return start_idx, end_idx

    def _get_strategy_idx(self):
        if self._current_index in range(0, self._bitflip_1_1_num_mutations):
            self._strategy_idx = 0
            self._base_number += self._bitflip_1_1_num_mutations
        elif self._current_index in range(self._base_number, self._base_number + self._bitflip_2_1_num_mutations):
            self._strategy_idx += 1
            self._base_number += self._bitflip_2_1_num_mutations
        elif self._current_index in range(self._base_number, self._base_number + self._bitflip_4_1_num_mutations):
            self._strategy_idx += 1
            self._base_number += self._bitflip_4_1_num_mutations
        elif self._current_index in range(self._base_number, self._base_number + self._bitflip_8_8_num_mutations):
            self._strategy_idx += 1
            self._base_number += self._bitflip_8_8_num_mutations
        elif self._current_index in range(self._base_number, self._base_number + self._bitflip_16_8_num_mutations):
            self._strategy_idx += 1
            self._base_number += self._bitflip_16_8_num_mutations
        elif self._current_index in range(self._base_number, self._base_number + self._bitflip_32_8_num_mutations):
            self._strategy_idx += 1
            self._base_number += self._bitflip_32_8_num_mutations
        elif self._current_index in range(self._base_number, self._base_number + self._arith_8_8_num_mutations):
            self._strategy_idx += 1
            self._base_number += self._arith_8_8_num_mutations
        elif self._current_index in range(self._base_number, self._base_number + self._arith_16_8_num_mutations):
            self._strategy_idx += 1
            self._base_number += self._arith_16_8_num_mutations
        elif self._current_index in range(self._base_number, self._base_number + self._arith_32_8_num_mutations):
            self._strategy_idx += 1
            self._base_number += self._arith_32_8_num_mutations
        return

    def _mutate(self):
        self._get_strategy_idx()
        method_name = "_" + self._strategy[self._strategy_idx]
        method = getattr(self, method_name)
        method()

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

        return

    def _arith_16_8(self):

        pass

    def _arith_32_8(self):

        return
