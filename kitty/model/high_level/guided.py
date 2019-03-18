'''

'''
from kitty.model.high_level.base import BaseModel
from kitty.model.high_level.base import Connection
from kitty.core import KittyObject, KittyException, khash
from Queue import PriorityQueue


class GuidedModel(BaseModel):
    '''

    '''

    def __init__(self, name="GuidedModel"):
        """

        :param name:
        """
        super(GuidedModel, self).__init__(name)
        self._pass_det = False
        self._havoc = False
        self._splicing = False
        self._root = self.ROOT_NODE
        self._root_id = self._root.hash()
        self._graph = {}
        self._graph[self._root_id] = []
        self._sequence_idx = -1
        self._current_node = None


    def _get_ready(self):
        if not self._ready:





            pass


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
            self.check_loops_in_grpah(conn.dst, visited + [conn.src])

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








class Queue(PriorityQueue):
    """

    """
    def __init__(self, name='Queue'):
        """

        :param name:
        """
        super(Queue, self).__init__(name)
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



