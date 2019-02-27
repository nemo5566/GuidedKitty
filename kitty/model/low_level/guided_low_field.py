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
        self._num_mutations = self._data_len_bits*3 - 4 + self._data_len_bytes*3 - 4 + (10*self._data_len_bytes - 16) * arith_max
        self._strategy = ["bitflip 1/1", "bitflip 2/1", "bitflip 4/1", "bitflip 8/8", "bitflip 16/8", "bitflip 32/8", "arith 8/8", "arith 16/8", "arith 32/8"]
    def _start_end(self):
        start_idx = self._current_index
        end_idx = start_idx + self._num_bits
        return start_idx, end_idx

    def _mutate(self):
        new_val = BitArray(self._default_value).copy()
        start, end = self._start_end()
        new_val.invert(range(start, end))
        self.set_current_value(Bits(new_val))

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