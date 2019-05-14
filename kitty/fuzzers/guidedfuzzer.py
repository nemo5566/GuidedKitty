
"""

"""
import time
import traceback
from kitty.fuzzers.base import BaseFuzzer
from kitty.data.report import Report

CAL_CYCLES = 4
CAL_CYCLES_LONG = 40
TOTAL_CAL_US = 0
TOTAL_CAL_CYCLES = 0
MAP_SIZE = 65536


class GuidedFuzzer(BaseFuzzer):
    '''
    ServerFuzzer is a class that is designed to fuzz servers.
    It does not create the mutations, as those are created by the Session object.
    The idea is to go through every path in the model, execute all requsets in
    the path, and mutating the last request.
    '''

    def __init__(self, name='GuidedFuzzer', logger=None, option_line=None, fast_cal=False):
        '''
        :param name: name of the object
        :param logger: logger for the object (default: None)
        :param option_line: cmd line options to the fuzzer
        '''
        super(GuidedFuzzer, self).__init__(name, logger, option_line)
        self.fast_cal = fast_cal

    def _start(self):
        self.logger.info('should keep running? %s' % self._keep_running())
        while self._next_mutation():
            sequence = self.model.get_sequence()
            try:
                self._run_sequence(sequence)
            except Exception as e:
                self.logger.error('Error occurred while fuzzing: %s', repr(e))
                self.logger.error(traceback.format_exc())
                break
        self._end_message()

    def _test_environment(self):
        try:
            if self._perform_dry_run():
                raise Exception('Environment test failed')
        except:
            self.logger.info('Environment test failed')
            raise

    def _perform_dry_run(self):
        queue_entry = self.model.get_queue()
        cal_failures = 0
        q = queue_entry._queue
        while q:
            res = self.calibrate_case(q, queue_entry)
            q = q.next

    def _pre_test(self):
        pass

    def calibrate_case(self, queue, queue_entry):
        """
        Calibrate a new test case. This is done when processing the input directory
        to warn about flaky or otherwise problematic test cases early on; and when
        new paths are discovered to detect variable behavior and so on.
        :return:
        """
        global TOTAL_CAL_US, TOTAL_CAL_CYCLES
        first_trace = [0]*MAP_SIZE
        var_bytes = [0]*MAP_SIZE
        new_bits = 0
        # TODO: var_bytes should be set global
        stage_max = 2 if self.fast_cal else CAL_CYCLES
        self._test_info()
        session_data = self.target.get_session_data()
        sequence = queue.sequence
        start_us = int(time.time() * 1000)
        j = 0
        while j < stage_max:
            run_res, trace_bits, pos_res = self._run_sequence(sequence)
            cksum = hash(str(trace_bits))
            if queue.exec_cksum != cksum:
                hnb = queue_entry.has_new_bits(trace_bits)
                if hnb > new_bits:
                    new_bits = hnb
            #     if queue.exec_cksum:
            #         i = 0
            #         while i < MAP_SIZE:
            #             if not var_bytes[i] and first_trace[i] != trace_bits[i]:
            #                 var_bytes[i] = 1
            #                 stage_max = CAL_CYCLES_LONG
            #                 print "Change to CAL_LONG"
            #             i += 1
            #     else:
            #         queue.exec_cksum = cksum
            #         first_trace = trace_bits
            j += 1
        stop_us = int(time.time() * 1000)
        TOTAL_CAL_US += start_us - stop_us
        TOTAL_CAL_CYCLES += stage_max
        queue.exec_us = (stop_us - start_us)/stage_max
        queue.bitmap_size = queue_entry.get_bitmap_size(trace_bits)
        # queue.handicap =
        queue.cal_failed = 0
        queue_entry.update_bitmap_score(queue, trace_bits)
        if new_bits == 2 and queue.has_new_cov == 0:
            queue.has_new_cov = 1
            queue_entry.queued_with_cov += 1
        return

    def _run_sequence(self, sequence):
        '''
        Run a single sequence
        '''
        self._check_pause()
        self._pre_test()
        trace_bits = [0] * MAP_SIZE
        session_data = self.target.get_session_data()
        self._test_info()
        resp = None
        for edge in sequence:
            if edge.callback:
                edge.callback(self, edge, resp)
            session_data = self.target.get_session_data()
            node = edge.dst
            node.set_session_data(session_data)
            resp, tb = self._transmit(node)
            i = 0
            trace_bits_hash = hash(str(trace_bits))
            if not trace_bits_hash == hash(str(tb)):
                while i < MAP_SIZE:
                    if trace_bits[i] or tb[i]:
                        trace_bits[i] = trace_bits[i] | tb[i]
                    i += 1
        post_res = self._post_test()
        return resp, trace_bits, post_res

    def _transmit(self, node):
        '''
        Transmit node data to target.

        :type node:  Template
        :param node: node to transmit
        :return: response if there is any
        '''
        payload = node.render().tobytes()
        self._last_payload = payload
        try:
            return self.target.transmit(payload)
        except Exception as e:
            self.logger.error('Error in transmit: %s', e)
            raise

    def _post_test(self):
        '''
        :return: True if test failed
        '''
        failure_detected = False
        self.target.post_test(self.model.current_index())
        report = self._get_report()
        status = report.get_status()
        if self._in_environment_test:
            return status != Report.PASSED
        if status != Report.PASSED:
            self._store_report(report)
            self.user_interface.failure_detected()
            failure_detected = True
            self.logger.warning('!! Failure detected !!')
        elif self.config.store_all_reports:
            self._store_report(report)
        if failure_detected:
            self.session_info.failure_count += 1
        self._store_session()
        if self.config.delay_secs:
            self.logger.debug('delaying for %f seconds', self.config.delay_secs)
            time.sleep(self.config.delay_secs)
        return failure_detected