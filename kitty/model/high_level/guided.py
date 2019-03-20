'''

'''
from kitty.model.high_level.base import BaseModel
from kitty.model.high_level.base import Connection
from kitty.core import KittyObject, KittyException, khash
from Queue import PriorityQueue
import os
from bitstring import Bits, BitArray
import time


class GuidedModel(BaseModel):
    '''

    '''

    def __init__(self, name="GuidedModel", indir=None):
        """

        :param name:
        """
        super(GuidedModel, self).__init__(name)
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


    def _get_ready(self):
        if not self._ready:
            if self.indir:
                KittyException("indir is None")
            else:
                self._queue_path = os.path.join(self.indir, "queue")
                os.mkdir(self._queue_path)
            self.check_loops_in_guided()
            num = 0
            self._sequences = self._get_sequences()
            assert len(self._sequences)
            self._reversquences = self._sequences[::-1]
            self._init_queue()

            # for sequence in self._sequences:
            #     num += sequence[-1].dst.num_mutations()
            # self._num_mutations = num
            # self._ready = True
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
            sqfilename = os.path.join(self.indir, sqname)
            f = open(sqfilename, "wb")
            sqbit.tofile(f)
            f.close()
            self._queue._add_to_queue(sqfilename, sqlen)

    def num_mutations(self):
        '''
        :return: number of mutations in the model
        '''
        self._get_ready()
        return self._num_mutations

    def _get_sequences(self, sequence=[]):
        sequences = []
        node = self._root if len(sequence) == 0 else sequence[-1].dst
        for conn in self._graph[node.hash()]:
            new_sequence = sequence + [conn]
            sequences.append(new_sequence)
            sequences.extend(self._get_sequences(new_sequence))
        return sequences

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


class QueueNode(KittyObject):
    """

    """
    def __init__(self, name='QueueNode'):
        super(QueueNode, self).__init__(name)
        self.fname = None
        self.len = 0
        self.cal_failed = False
        self.was_fuzzed = False
        self.passed_det = False
        self.has_new_con = False
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
        self._queue_list = []
        self._queue = None
        self._queue_cur = None
        self._queue_top = None
        self._queue_prev100 = None
        self._reversquences = None
        self._cur_depth = 0
        self._max_depth = 1000
        self._queue_paths = 0
        self._pending_not_fuzzed = 0
        self._cycles_no_finds = 0
        self._last_path_time = None

    def _add_to_queue(self, sqname, len, pass_det=0):
        if sqname == None or len == None:
            KittyException("add to queue error")
        q = QueueNode()
        q.fname = sqname
        q.len = len
        q.depth = self._cur_depth + 1

        self._queue_list.append(q)

        if q.depth > self._max_depth:
            self._max_depth = q.depth

        if self._queue_top:
            self._queue_top.next = q
            self._queue_top = q
        else:
            self._queue_prev100 = self._queue = self._queue_top = q

        self._queue_paths += 1
        self._pending_not_fuzzed += 1
        self._cycles_no_finds = 0

        if self._queue_paths // 100:
            self._queue_prev100.next = q
            self._queue_prev100 = q

        self._last_path_time = int(time.time()*1000)

    def _cull_queue(self):
        pass

    def _save_if_interesting(self):
        pass

    def _mark_as_det_done(self):
        pass
