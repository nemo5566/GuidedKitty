
"""

"""
import time
import traceback
from kitty.fuzzers.base import BaseFuzzer
from kitty.data.report import Report

CAL_CYCLES = 8
TOTAL_CAL_US = 0
TOTAL_CAL_CYCLES = 0


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
        stage_max = 3 if self.fast_cal else CAL_CYCLES
        self._test_info()
        session_data = self.target.get_session_data()
        sequence = queue.sequence
        start_us = int(time.time() * 1000)
        for i in range(0, stage_max):
            cksum = 0
            res = self._run_sequence(sequence)
        stop_us = int(time.time() * 1000)
        TOTAL_CAL_US += start_us - stop_us
        TOTAL_CAL_CYCLES += stage_max
        queue.exec_us = (start_us - stop_us)/stage_max
        # queue.bitmap_size =
        # queue.handicap =
        queue.cal_failed = 0
        queue_entry.update_bitmap_score(queue)


    def _run_sequence(self, sequence):
        '''
        Run a single sequence
        '''
        self._check_pause()
        self._pre_test()
        session_data = self.target.get_session_data()
        self._test_info()
        resp = None
        for edge in sequence:
            if edge.callback:
                edge.callback(self, edge, resp)
            session_data = self.target.get_session_data()
            node = edge.dst
            node.set_session_data(session_data)
            resp = self._transmit(node)
        return self._post_test()

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