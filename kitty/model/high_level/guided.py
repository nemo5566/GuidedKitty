'''
written by ly
'''
from kitty.model.high_level.base import BaseModel
from kitty.model.high_level.base import Connection
from kitty.core import KittyObject, KittyException, khash
from bitstring import Bits, BitArray

import os
import time
import random
import math

INDIR = None
OUTDIR = None
QUEUEPATH = None
HAVOC_CYCLES_INIT = 26
HAVOC_CYCLES = 256
SPLICE_HAVOC = 32
HAVOC_BLK_SMALL = 32  # type: int
HAVOC_BLK_MEDIUM = 128
HAVOC_BLK_LARGE = 1500
HAVOC_BLK_XL = 32768
HAVOC_MAX_MULT = 16
SPLICE_CYCLES = 15
MAP_SIZE = 65536
SKIP_TO_NEW_PROB = 99 #/* ...when there are new, pending favorites */
SKIP_NFAV_OLD_PROB = 95 #/* ...no new favs, cur entry already fuzzed */
SKIP_NFAV_NEW_PROB = 75 #/* ...no new favs, cur entry not fuzzed yet */


class GuidedModel(BaseModel):
    """

    """

    def __init__(self, name="GuidedModel", indir=None, outdir=None, skip_det=False):
        """

        :param name:
        """
        super(GuidedModel, self).__init__(name)
        self.skip_det = skip_det
        self.outdir = outdir
        self.indir = indir
        self._pass_det = False
        self._havoc = False
        self._splicing = False
        self._root = self.ROOT_NODE
        self._root_id = self._root.hash()
        self._graph = {}
        self._graph[self._root_id] = []
        self._sequence_idx = -1
        self._current_node = None
        self._queue = QueueEntry()
        self._det_num_mutations = 0
        self.skip_run = False

    def _get_ready(self):
        if not self._ready:
            if self.indir and self.outdir:
                KittyException("indir or outdir is None")
            global INDIR
            INDIR = self.indir
            global OUTDIR
            OUTDIR = self.outdir
            self.check_loops_in_guided()
            num = 0
            self._sequences = self._get_sequences()
            for sequence in self._sequences:
                num += sequence[-1].dst.num_mutations()
            self._det_num_mutations = num
            self._sequences = self._get_sequences()
            assert len(self._sequences)
            self._reversquences = self._sequences[::-1]
            self._init_queue()
            self._queue.pivot_inputs()
            self._load_extras()
            self._ready = True
            # self._update_state(0)

    def _init_queue(self):
        for sq in self._reversquences:
            sqname = ""
            sqlen = 0
            sqbit = BitArray()
            for i in sq:
                sqname = sqname + "->" + i.dst.get_name()
                sqrender = i.dst.render()
                sqlen += sqrender.len
                sqbit.append(sqrender)
            sqname = "root" + sqname
            cwd = os.getcwd()
            cwdin = os.path.join(cwd, INDIR)
            sqfilename = os.path.join(cwdin, sqname)
            with open(sqfilename, "wb") as f:
                sqbit.tofile(f)
            f.close()
            self._queue.add_to_queue(sqfilename, sq, sqlen)
            self._queue.queue_cur = self._queue.queue

    def _load_extras(self):
        # TODO: need to load the extras in fields
        pass

    def get_test_info(self):
        info = super(GuidedModel, self).get_test_info()
        node_info = self._get_node().get_info()
        info['node'] = node_info
        info['sequence']['index'] = self._sequence_idx
        return info

    def _get_node(self):
        return self._queue.queue_cur.sequence[-1].dst

    def _mutate(self):
        self.skip_run = False
        self.skip_run = self._queue._mutate()

    def num_mutations(self):
        '''
        :return: number of mutations in the model
        '''
        self._get_ready()
        return self._det_num_mutations + 999999999

    def _get_sequences(self, sequence=[]):
        sequences = []
        node = self._root if len(sequence) == 0 else sequence[-1].dst
        for conn in self._graph[node.hash()]:
            new_sequence = sequence + [conn]
            sequences.append(new_sequence)
            sequences.extend(self._get_sequences(new_sequence))
        return sequences

    def get_sequence(self):
        self._get_ready()
        assert self._queue.queue_cur.sequence
        return self._queue.queue_cur.sequence[:]

    def get_queue(self):
        self._get_ready()
        assert self._queue
        return self._queue

    def hash(self):
        hashed = super(GuidedModel, self).hash()
        skeys = sorted(self._graph.keys())
        for key in skeys:
            for conn in self._graph[key]:
                t_hashed = conn.dst.hash()
                self.logger.debug('hash of template %s is %s' % (conn.dst.get_name(), t_hashed))
                hashed = khash(hashed, t_hashed)
        self.logger.debug('hash of model is %s' % hashed)
        return hashed

    def check_loops_in_guided(self, current=None, visited=[]):
        '''
        :param current: current node to check if visited
        :param visited: list of visited fields
        :raise: KittyException if loop found
        '''
        if current in visited:
            path = ' -> '.join(v.get_name() for v in (visited + [current]))
            raise KittyException('loop detected in model: %s' % path)
        current = current if current else self._root
        for conn in self._graph[current.hash()]:
            self.check_loops_in_guided(conn.dst, visited + [conn.src])

    def connect(self, src, dst=None, callback=None):
        '''
        :param src: source node, if dst is None it will be destination node and the root (dummy) node will be source
        :param dst: destination node (default: None)
        :type callback: func(fuzzer, edge, response) -> None
        :param callback: a function to be called after the response for src received and before dst is sent
        '''
        assert src
        if dst is None:
            dst = src
            src = self._root
        src_id = src.hash()
        dst_id = dst.hash()
        if src_id not in self._graph:
            raise KittyException('source node id (%#x) (%s) is not in the node list ' % (src_id, src))
        self._graph[src_id].append(Connection(src, dst, callback))
        if dst_id not in self._graph:
            self._graph[dst_id] = []

    def save_if_interesting(self, run_res, tracebits, e):
        hnb = self._queue.has_new_bits(tracebits)
        if not hnb:
            self._queue.total_carshes += 1
            return 0
        qname = "id:%06u,src:%06u" % (self._queue.queue_paths, self._queue.current_entry)
        sq = self._queue.queue_cur.sequence
        sq[-1].dst._det_finish = True
        sqlen = 0
        sqbit = BitArray()
        for i in sq:
            sqrender = i.dst.render()
            sqlen += sqrender.len
            sqbit.append(sqrender)
        sqfilename = os.path.join(self._queue.queue_out_path, qname)
        with open(sqfilename, "wb") as f:
            sqbit.tofile(f)
        f.close()
        self._queue.add_to_queue(qname, sq, sqlen)
        if hnb == 2:
            self._queue.queue_top.has_new_cov = 1
            self._queue.queued_with_cov += 1
        return 1




class QueueNode(KittyObject):
    """

    """

    def __init__(self, name='QueueNode'):
        super(QueueNode, self).__init__(name)
        self.fname = None
        self.len = 0
        self.sequence = None
        self.cal_failed = False
        self.was_fuzzed = False
        self.passed_det = False
        self.has_new_cov = 0
        self.var_behavior = None
        self.favored = False

        self.bitmap_size = 0
        self.exec_cksum = None

        self.exec_us = 0
        self.handicap = 0
        self.depth = 0
        self.trace_mini = None
        self.tc_ref = 0
        self.next = None
        self.next_100 = None


class QueueEntry(KittyObject):
    """

    """

    def __init__(self, name='QueueEntry'):
        """

        :param name:
        """
        super(QueueEntry, self).__init__(name)
        self._pending_favored = 0
        self._splicing_with = -1
        self._extras_cnt = 0
        self._a_extras_cnt = 0
        self._queue_list = []
        self.queue = None
        self.queue_cur = None
        self.queue_top = None
        self._queue_prev100 = None
        self._reversquences = None
        self._cur_depth = 0
        self._max_depth = 1000
        self.queue_paths = 0
        self._pending_not_fuzzed = 0
        self._cycles_no_finds = 0
        self._last_path_time = None
        self._queue_cycle = 0
        self.current_entry = 0
        self._queue_cur_change = False
        self._havoc_max = 0
        self._splicing_max = 0
        self._splicing_cycle = 0
        self._havoc_stage_cur = 0
        self._splicing_stage_cur = 0
        self._perf_score = 0
        self._run_over10m = False  # Run time over 10 minutes?
        self._havoc_queue = 0
        self._unique_crashes = 0
        self._new_hit_cnt = 0
        self._havoc_num = 0
        self._stop_soon = False
        self._top_rated = [None] * MAP_SIZE
        self._score_changed = 0
        self._virgin_bits = [-1]*MAP_SIZE
        self._bitmap_changed = 0
        self.queued_with_cov = 0
        self._queued_favored = 0
        self._dumb_mode = False
        self._queued_discovered = 0
        self.total_cal_us = 0
        self.total_cal_cycles = 0
        self.total_bitmap_size = 0
        self.total_bitmap_entries = 0
        self.havoc_div = 1
        self.queue_out_path = ""
        self.total_carshes = 0
        # global HAVOC_CYCLES, HAVOC_CYCLES_INIT, SPLICE_HAVOC, HAVOC_BLK_LARGE, HAVOC_BLK_SMALL, HAVOC_BLK_MEDIUM, \
        #     HAVOC_BLK_XL, HAVOC_MAX_MULT, SPLICE_CYCLES

    def add_to_queue(self, sqname, sequence, length, passed_det=False):
        """

        :param sqname:
        :param sequence:
        :param length:
        :param passed_det:
        :return:
        """
        if sqname == None or len == None:
            KittyException("add to queue error")
        q = QueueNode()
        q.fname = sqname
        q.sequence = sequence
        q.len = length
        q.depth = self._cur_depth + 1
        q.passed_det = passed_det

        self._queue_list.append(q)

        if q.depth > self._max_depth:
            self._max_depth = q.depth

        if self.queue_top:
            self.queue_top.next = q
            self.queue_top = q
        else:
            self._queue_prev100 = self.queue = self.queue_top = q

        self.queue_paths += 1
        self._pending_not_fuzzed += 1
        self._cycles_no_finds = 0

        if self.queue_paths // 100:
            self._queue_prev100.next = q
            self._queue_prev100 = q

        self._last_path_time = int(time.time() * 1000)

    def pivot_inputs(self):
        pivot_id = 0
        q = self.queue
        self.queue_out_path = os.path.join(OUTDIR, "queue%s" % time.strftime("%Y%m%d-%H%M%S"))
        global QUEUEPATH
        QUEUEPATH = self.queue_out_path
        os.mkdir(self.queue_out_path)
        while q:
            fname = os.path.split(q.fname)[-1]
            qname = "id:%06u,orig:%s" % (pivot_id, fname)
            nfn = os.path.join(self.queue_out_path, qname)
            os.link(q.fname, nfn)
            q.fname = nfn

            if q.passed_det:
                self._mark_as_det_done(q)

            q = q.next
            pivot_id += 1

    def _cull_queue(self):
        temp_v = [1]*MAP_SIZE
        if self._dumb_mode or not self._score_changed:
            return
        self._score_changed = 0
        self._queued_favored = 0
        self._pending_favored = 0
        q = self.queue
        while q:
            q.favored = 0
            q = q.next
        i = 0
        while i < MAP_SIZE:
            if self._top_rated[i] and temp_v[i]:
                j = MAP_SIZE - 1
                while j >= 0:
                    if self._top_rated[i].trace_mini[j]:
                        temp_v[j] = 0
                    j -= 1
                self._top_rated[i].favored = 1
                self._queued_favored += 1
                if not self._top_rated[i].was_fuzzed:
                    self._pending_favored += 1
            i += 1
        q = self.queue
        while q:
            self._mark_as_redundant(q, q.favored)
            q = q.next

    def _save_if_interesting(self):
        pass

    def _mark_as_det_done(self, queue):
        pass

    def _mutate(self):


        if self._queue_cur_change:
            self._cull_queue()
            self._calculate_score(self.queue_cur)
            self._queue_cur_change = False
        if self._pending_favored:
            if self.queue_cur.was_fuzzed and not self.queue_cur.favored:
                if random.randint(1, 100) < SKIP_TO_NEW_PROB:
                    return True
        elif not self._dumb_mode and not self.queue_cur.favored and self.queue_paths > 10:
            if self._queue_cycle > 1 and not self.queue_cur.was_fuzzed:
                if random.randint(1, 100) < SKIP_NFAV_NEW_PROB:
                    return True
            else:
                if random.randint(1, 100) < SKIP_NFAV_OLD_PROB:
                    return True

        if not self.queue_cur.passed_det:
            self._do_det()
        else:
            self._do_havoc_and_splicing()

        self._abandon_entry()

        if not self.queue_cur:
            self._queue_cycle += 1
            self.current_entry = 0
            self.queue_cur = self.queue
        return False

    def _do_det(self):
        node = self.queue_cur.sequence[-1].dst
        if node.mutate():
            return
        else:
            node._det_finish = True
            self.queue_cur.passed_det = True
            node.reset()

    def _do_havoc_and_splicing(self):
        self.logger.debug("Start Havoc and Splicing >>>>>>>>>>>>>>>>>>>>")
        while True:
            if self._do_havoc():
                # TODO: Add the following code to the postrun
                # if self._queue_paths != self._havoc_queue:
                #     if self._perf_score <= HAVOC_MAX_MULT * 100:
                #         self._havoc_max *= 2
                #         self._perf_score *= 2
                #     self._havoc_queue = self._queue_paths
                return
            else:
                self._new_hit_cnt = self.queue_paths + self._unique_crashes  # ????
                if self._do_splicing():
                    self._havoc_num = 0
                    break
                else:
                    self._havoc_num = 0


    def _do_havoc(self):
        self.logger.debug("Havoc>>>>>>>>>>>>>>>>>>>>>>>>")
        if not self._splicing_cycle:
            self._havoc_max = (HAVOC_CYCLES_INIT if self.queue_cur.passed_det else HAVOC_CYCLES) * (
                    self._perf_score / self.havoc_div / 100)  # need to add havoc_div according to exec secs
        else:
            self._havoc_max = SPLICE_HAVOC * self._perf_score / self.havoc_div / 100
        self._havoc_queue = self.queue_paths
        node = self.queue_cur.sequence[-1].dst
        node._current_index = 1
        node_val = BitArray(node.render()).copy()
        if self._havoc_max < 16:
            self._havoc_max = 16

        if self._havoc_num < self._havoc_max:
            use_stacking = int(math.pow(2, random.randint(1, 8)))
            for i in range(use_stacking):
                temp_len = node_val.len
                k = random.randint(1, 15 + (2 if self._extras_cnt + self._a_extras_cnt else 0))
                if k == 1:
                    ranstart = random.randint(0, temp_len - 1)
                    node_val.invert(range(ranstart, ranstart + 1))
                    node.set_current_value(Bits(node_val))
                elif k == 2:
                    # TODO add interesting value
                    pass
                elif k == 3:
                    # Set word to interesting value, randomly choosing endian.
                    pass
                elif k == 4:
                    # Set dword to interesting value, randomly choosing endian.
                    pass
                elif k == 5:
                    # Randomly subtract from byte.
                    if temp_len < 8:
                        continue
                    ranstart = random.randint(0, temp_len - 8)
                    tmp_uint = node_val[ranstart: ranstart + 8].uint - 1
                    tmp_uint &= 0xff
                    tmp_b = BitArray(uint=tmp_uint, length=8)
                    del node_val[ranstart: ranstart + 8]
                    node_val.insert(tmp_b, ranstart)
                    node.set_current_value(Bits(node_val))
                elif k == 6:
                    if temp_len < 8:
                        continue
                    ranstart = random.randint(0, temp_len - 8)
                    tmp_uint = node_val[ranstart: ranstart + 8].uint + 1
                    tmp_uint &= 0xff
                    tmp_b = BitArray(uint=tmp_uint, length=8)
                    del node_val[ranstart: ranstart + 8]
                    node_val.insert(tmp_b, ranstart)
                    node.set_current_value(Bits(node_val))
                elif k == 7:
                    if temp_len < 16:
                        continue
                    ranstart = random.randint(0, temp_len - 16)
                    if random.randint(0, 1):
                        tmp_uint = node_val[ranstart: ranstart + 16].uintbe - 1
                        tmp_uint &= 0xffff
                        tmp_b = BitArray(uintbe=tmp_uint, length=16)
                        del node_val[ranstart: ranstart + 16]
                        node_val.insert(tmp_b, ranstart)
                        node.set_current_value(Bits(node_val))
                    else:
                        tmp_uint = node_val[ranstart: ranstart + 16].uintle - 1
                        tmp_uint &= 0xffff
                        tmp_b = BitArray(uintle=tmp_uint, length=16)
                        del node_val[ranstart: ranstart + 16]
                        node_val.insert(tmp_b, ranstart)
                        node.set_current_value(Bits(node_val))
                elif k == 8:
                    if temp_len < 16:
                        continue
                    ranstart = random.randint(0, temp_len - 16)
                    if random.randint(0, 1):
                        tmp_uint = node_val[ranstart: ranstart + 16].uintbe + 1
                        tmp_uint &= 0xffff
                        tmp_b = BitArray(uintbe=tmp_uint, length=16)
                        del node_val[ranstart:  ranstart + 16]
                        node_val.insert(tmp_b, ranstart)
                        node.set_current_value(Bits(node_val))
                    else:
                        tmp_uint = node_val[ranstart:  ranstart + 16].uintle + 1
                        tmp_uint &= 0xffff
                        tmp_b = BitArray(uintle=tmp_uint, length=16)
                        del node_val[ranstart:  ranstart + 16]
                        node_val.insert(tmp_b, ranstart)
                        node.set_current_value(Bits(node_val))
                elif k == 9:
                    if temp_len < 32:
                        continue
                    ranstart = random.randint(0, temp_len - 32)
                    if random.randint(0, 1):
                        tmp_uint = node_val[ranstart:  ranstart + 32].uintbe - 1
                        tmp_uint &= 0xffffffff
                        tmp_b = BitArray(uintbe=tmp_uint, length=32)
                        del node_val[ranstart: ranstart + 32]
                        node_val.insert(tmp_b, ranstart)
                        node.set_current_value(Bits(node_val))
                    else:
                        tmp_uint = node_val[ranstart: ranstart + 32].uintle - 1
                        tmp_uint &= 0xffffffff
                        tmp_b = BitArray(uintle=tmp_uint, length=32)
                        del node_val[ranstart: ranstart + 32]
                        node_val.insert(tmp_b, ranstart)
                        node.set_current_value(Bits(node_val))
                elif k == 10:
                    if temp_len < 32:
                        continue
                    ranstart = random.randint(0, temp_len - 32)
                    if random.randint(0, 1):
                        tmp_uint = node_val[ranstart: ranstart + 32].uintbe + 1
                        tmp_uint &= 0xffffffff
                        tmp_b = BitArray(uintbe=tmp_uint, length=32)
                        del node_val[ranstart: ranstart + 32]
                        node_val.insert(tmp_b, ranstart)
                        node.set_current_value(Bits(node_val))
                    else:
                        tmp_uint = node_val[ranstart: ranstart + 32].uintle + 1
                        tmp_uint &= 0xffffffff
                        tmp_b = BitArray(uintle=tmp_uint, length=32)
                        del node_val[ranstart: ranstart + 32]
                        node_val.insert(tmp_b, ranstart)
                        node.set_current_value(Bits(node_val))
                elif k == 11:
                    if temp_len < 8:
                        continue
                    ranstart = random.randint(0, temp_len - 8)
                    node_val[ranstart: ranstart + 8] ^= Bits(uint=random.randint(1, 255), length=8)
                    node.set_current_value(Bits(node_val))
                elif k == 12 or k == 13:
                    #  Delete bytes. We're making this a bit more likely
                    #  than insertion (the next option) in hopes of keeping
                    #  files reasonably small.
                    if temp_len < 8:
                        continue
                    del_len = self._choose_block_len(temp_len / 8)
                    del_len *= 8
                    ranstart = random.randint(0, temp_len - del_len)
                    del node_val[ranstart: ranstart + del_len - 1]
                    node.set_current_value(Bits(node_val))
                    temp_len -= del_len
                elif k == 14:
                    # Clone bytes (75%) or insert a block of constant bytes (25%).
                    if temp_len < 8:
                        continue
                    actually_clone = random.randint(0, 3)
                    clone_to = random.randint(0, temp_len - 1)
                    if actually_clone:
                        clone_len = self._choose_block_len(temp_len / 8)
                        clone_len *= 8
                        clone_from = random.randint(0, temp_len - clone_len)
                        temp_clone = node_val[clone_from: min(clone_from + clone_len - 1, temp_len - 1)]
                        node_val.insert(temp_clone, clone_to)
                    else:
                        clone_len = self._choose_block_len(HAVOC_BLK_XL)
                        temp_clone = BitArray()
                        for _ in range(0, clone_len):
                            temp_clone += BitArray(uint=random.randint(1, 255), length=8)
                        clone_len = temp_clone.len
                        node_val.insert(temp_clone, clone_to)
                    temp_len += clone_len
                    node.set_current_value(Bits(node_val))

                elif k == 15:
                    # Overwrite bytes with a randomly selected chunk (75%) or fixed bytes (25%).
                    if temp_len < 8:
                        continue
                    actually_clone = random.randint(0, 3)
                    clone_len = self._choose_block_len(temp_len / 8)
                    clone_len *= 8
                    clone_to = random.randint(0, temp_len - clone_len)
                    if actually_clone:
                        clone_from = random.randint(0, temp_len - clone_len)
                        temp_clone = node_val[clone_from: min(clone_from + clone_len - 1, temp_len - 1)]
                        del node_val[clone_to: clone_to + clone_len]
                        node_val.insert(temp_clone, clone_to)
                    else:
                        temp_clone = BitArray()
                        for _ in range(0, clone_len / 8):
                            temp_clone += BitArray(uint=random.randint(1, 255), length=8)
                        del node_val[clone_to: clone_to + clone_len]
                        node_val.insert(temp_clone, clone_to)
                    node.set_current_value(Bits(node_val))

                # Values 15 and 16 can be selected only if there are any extras
                # present in the dictionaries.
                elif k == 16:
                    # Overwrite bytes with an extra.
                    pass
                elif k == 17:
                    # insert an extra. Do the same dice-rolling stuff as for the previous case.
                    pass
            self._havoc_num += 1
            return 1
        else:
            return 0

    def _do_splicing(self):
        self.logger.debug("Splicing>>>>>>>>>>>>>>>>>>>>>>>")
        target = None
        f_loc = -1
        l_loc = -1
        while f_loc < 0 or l_loc < 1 or f_loc == l_loc:
            target = None
            while not target:
                if self._splicing_cycle < SPLICE_CYCLES and self.queue_paths > 1 and self.queue_cur.len > 8:
                    self._splicing_cycle += 1
                    while True:
                        tid = random.randint(0, self.queue_paths - 1)
                        if tid != self.current_entry:
                            break
                    self._splicing_with = tid
                    target = self.queue
                    while tid >= 100:
                        target = target.next_100
                        tid -= 100
                    while tid > 0:
                        target = target.next
                        tid -= 1
                    while target and target.sequence[-1].dst.render().len < 16 or target == self.queue_cur:
                        target = target.next
                        self._splicing_with += 1
                    if not target:
                        break
                    # with open(target.fname, "rb") as tf:
                    #     tbuff = tf.read()
                    # tf.close()
                    # with open(self._queue_cur.fname, "rb") as qf:
                    #     qbuff = qf.read()
                    # qf.close()
                    tnode = target.sequence[-1].dst
                    tbuff = BitArray(tnode.render()).copy()
                    qnode = self.queue_cur.sequence[-1].dst
                    qbuff = BitArray(qnode.render()).copy()
                    minlen = min(len(tbuff), len(qbuff))
                    for i in range(0, minlen):
                        if qbuff[i] != tbuff[i]:
                            l_loc = i
                            if f_loc == -1:
                                f_loc = i
                else:
                    self._splicing_cycle = 0
                    return 1
        split_at = f_loc + random.randint(1, l_loc - f_loc)
        tlen = target.len
        newbuff = tbuff[0: split_at]  # type: str
        newbuff += qbuff[split_at: tlen]
        qnode.set_current_value(newbuff)
        return 0

    def _abandon_entry(self):
        self._splicing_with = -1
        if not self._stop_soon and not self.queue_cur.cal_failed and not self.queue_cur.was_fuzzed:
            self.queue_cur.was_fuzzed = 1
            self._pending_not_fuzzed -= 1
            if self.queue_cur.favored:
                self._pending_favored -= 1
            self.queue_cur = self.queue_cur.next
            self.current_entry += 1
            self._queue_cur_change = True
        return


    def _update_queue_cur(self, target, newbuff):

        pass

    def _calculate_score(self, queue):
        avg_exec_us = self.total_cal_us/self.total_cal_cycles
        avg_bitmap_size = self.total_bitmap_size/self.total_bitmap_entries
        self._perf_score = 100
        if queue.exec_us * 0.1 > avg_exec_us:
            self._perf_score = 10
        elif queue.exec_us * 0.25 > avg_exec_us:
            self._perf_score = 25
        elif queue.exec_us * 0.5 > avg_exec_us:
            self._perf_score = 50
        elif queue.exec_us * 0.75 > avg_exec_us:
            self._perf_score = 75
        elif queue.exec_us * 4 < avg_exec_us:
            self._perf_score = 300
        elif queue.exec_us * 3 < avg_exec_us:
            self._perf_score = 200
        elif queue.exec_us * 2 < avg_exec_us:
            self._perf_score = 150

        if queue.bitmap_size * 0.3 > avg_bitmap_size:
            self._perf_score *= 3
        elif queue.bitmap_size * 0.5 > avg_bitmap_size:
            self._perf_score *= 2
        elif queue.bitmap_size * 0.75 > avg_bitmap_size:
            self._perf_score *= 1.5
        elif queue.bitmap_size * 3 < avg_bitmap_size:
            self._perf_score *= 0.25
        elif queue.bitmap_size * 2 < avg_bitmap_size:
            self._perf_score *= 0.5
        elif queue.bitmap_size * 1.5 < avg_bitmap_size:
            self._perf_score *= 0.75

        if queue.handicap >= 4:
            self._perf_score *= 4
            queue.handicap -= 4
        else:
            if queue.handicap:
                self._perf_score *= 2
                queue.handicap -= 1

        if 4 <= queue.depth <= 7:
            self._perf_score *= 2
        elif 8 <= queue.depth <= 13:
            self._perf_score *= 3
        elif 14 <= queue.depth <= 25:
            self._perf_score *= 4
        elif queue.depth > 25:
            self._perf_score *= 5

        if self._perf_score > HAVOC_MAX_MULT * 100:
            self._perf_score = HAVOC_MAX_MULT * 100
        return

    def save_if_interesting(self):
        pass

    def write_to_testcase(self):
        pass


    def _choose_block_len(self, limit):
        """
         Helper to choose random block len for block operations in fuzz_one().
         Doesn't return zero, provided that max_len is > 0.
        :param limit:
        :return:
        """
        min_value = max_value = 0
        rlim = min(self._queue_cycle, 3)
        if not self._run_over10m:
            rlim = 1
        tmp_r = random.randint(0, rlim)
        if tmp_r == 0:
            min_value = 1
            max_value = HAVOC_BLK_SMALL
        elif tmp_r == 1:
            min_value = HAVOC_BLK_SMALL
            max_value = HAVOC_BLK_MEDIUM
        else:
            if random.randint(0, 10):
                min_value = HAVOC_BLK_MEDIUM
                max_value = HAVOC_BLK_LARGE
            else:
                min_value = HAVOC_BLK_LARGE
                max_value = HAVOC_BLK_XL
        if min_value >= limit:
            min_value = 1
        return min_value + random.randint(0, min(max_value, limit) - min_value)

    def update_bitmap_score(self, queue, trace_bits):
        i = 0
        fav_factor = queue.exec_us * queue.len
        while i < MAP_SIZE:
            if trace_bits[i]:
                if self._top_rated[i]:
                    if fav_factor > self._top_rated[i].exec_us * self._top_rated[i].len:
                        i += 1
                        continue
                    if self._top_rated[i].tc_ref > 0:
                        self._top_rated[i].tc_ref -= 1
                        self._top_rated[i].trace_mini = None
                self._top_rated[i] = queue
                queue.tc_ref += 1
                if not queue.trace_mini:
                    queue.trace_mini = self._minimize_bits(trace_bits)
                self._score_changed = 1
            i += 1
        return

    def get_bitmap_size(self, trace_bits):
        i = 0
        size = 0
        while i < MAP_SIZE:
            size += trace_bits[i]
            i += 1
        return size

    def _minimize_bits(self, trace_bits):
        i = 0
        mini_bits = [0] * MAP_SIZE
        while i < MAP_SIZE:
            if trace_bits[i]:
                mini_bits[i] = 1
            i += 1
        return mini_bits

    def has_new_bits(self, trace_bits):
        i = 0
        ret = 0
        while i < MAP_SIZE:
            if trace_bits[i]:
                if self._virgin_bits[i] == -1:
                    ret = 2
                    self._virgin_bits[i] = trace_bits[i]
                    self._bitmap_changed = 1
                elif self._virgin_bits != trace_bits[i]:
                    if ret != 2:
                        ret = 1
                    self._virgin_bits[i] = trace_bits[i]
                    self._bitmap_changed = 1
            i += 1
        return ret

    def _mark_as_redundant(self, q, favored):
        pass
