import os
import socket
import socketserver
import sys
import threading
import time
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import custom_lb as lb


class EchoBackend(socketserver.BaseRequestHandler):
    """A local SOCKS5 backend that echoes data after CONNECT."""
    def handle(self):
        self.request.settimeout(3)
        if lb._recv_exact(self.request, 3) != b"\x05\x01\x00":
            return
        self.request.sendall(b"\x05\x00")
        if not lb._recv_exact(self.request, 10):
            return
        self.request.sendall(b"\x05\x00\x00\x01" + bytes(6))
        while data := self.request.recv(1024):
            self.request.sendall(data)


class BalancerTests(unittest.TestCase):
    def setUp(self):
        self.proxies = [("127.0.0.1", 9000 + i) for i in range(44)]
        state = patch.multiple(
            lb, _target_proxies=self.proxies.copy(), TOP_N_PROXIES=4, CHECK_MODE=1,
            _healthy_sorted_proxies=[], _in_use=Counter(), _round_robin_index=0,
            bootstrapped_controllers={}, packet_stats_per_proxy={}, _reloading_proxies=set(),
            _last_reload_time={}, _invalidated_during_check=set(), _stopping=threading.Event(),
            _full_recheck_needed_event=threading.Event(), api_client=Mock(),
        )
        state.start()
        self.addCleanup(state.stop)

    def audit(self, results):
        def check(host, port):
            result = results.get((host, port), (None, 0))
            if isinstance(result, Exception):
                raise result
            return result
        with patch.object(lb, "check_proxy_download_fixed", side_effect=check):
            lb._run_full_check_cycle()

    def test_health_checks_use_selected_backend_with_environment_proxy(self):
        # Exercise Requests' real environment merge without making external requests.
        expected = "socks5h://127.0.0.1:9000"
        observed = []

        def reply(adapter, request, **kwargs):
            scheme = request.url.split(":", 1)[0]
            observed.append(kwargs["proxies"][scheme])
            response = lb.requests.Response()
            response.status_code = 204 if scheme == "http" else 200
            response._content = b"test data"
            response._content_consumed = True
            return response

        env = dict(http_proxy="http://unrelated.invalid", https_proxy="http://unrelated.invalid")
        with patch.dict(os.environ, env, clear=True), patch.object(lb.requests.adapters.HTTPAdapter, "send", reply):
            self.assertEqual(lb.check_proxy_ping(*self.proxies[0], 1, 1)[1], 100)
            self.assertEqual(lb.check_proxy_download_fixed(*self.proxies[0])[1], 100)
        self.assertEqual(observed, [expected, expected])

    def test_top_four_rotate_and_all_healthy_fallbacks_stay_warm(self):
        self.audit({p: (score, 100) for score, p in enumerate(reversed(self.proxies), 1)})
        ranked = self.proxies[::-1]
        for first in ranked[:4] * 2:
            candidates = lb.get_candidate_proxies()
            self.assertEqual(candidates[0], first)
            self.assertCountEqual(candidates[:4], ranked[:4])
            self.assertEqual(candidates[4:], ranked[4:])
        lb.api_client.pause_all_except.assert_called_with(sorted(p[1] for p in ranked))

    def test_partial_outage_empty_pool_and_recovery(self):
        good = self.proxies[::11]
        results = {p: (i + 1, 100) for i, p in enumerate(good)}
        results.update(zip(self.proxies[1:5], [(float("inf"), 100), (float("nan"), 100),
                                               (1, 0), OSError("unavailable")]))
        self.audit(results)
        self.assertEqual(lb.get_candidate_proxies(), good)
        lb.api_client.pause_all_except.assert_called_with([p[1] for p in good])
        self.audit({})
        self.assertEqual(lb.get_candidate_proxies(), [])
        self.assertTrue(lb._full_recheck_needed_event.is_set())
        self.assertEqual(self.open_client()[1], 1)
        lb.api_client.pause_all_except.assert_called_with([])
        self.audit({self.proxies[7]: (1, 100)})
        self.assertEqual(lb.get_candidate_proxies(), [self.proxies[7]])
        self.assertEqual(lb.api_client.resume_all.call_count, 3)

    def test_reactive_event_wins_over_an_older_measurement(self):
        a, b = self.proxies[:2]
        lb._target_proxies = [a, b]
        self.audit({p: (1, 100) for p in (a, b)})

        def check(host, port):
            if (host, port) == b:
                lb.trigger_reactive_removal(a, "down after probe")
            return 1, 100

        with patch.object(lb, "check_proxy_download_fixed", side_effect=check):
            lb._run_full_check_cycle()
        self.assertEqual(lb.get_candidate_proxies(), [b])
        self.audit({p: (1, 100) for p in (a, b)})
        self.assertEqual(lb.get_candidate_proxies(), [a, b])

    def test_repeated_notifications_share_one_reload(self):
        proxy = self.proxies[0]
        entered, release = threading.Event(), threading.Event()

        def hup(signal):
            entered.set()
            release.wait(3)

        controller = Mock()
        controller.signal.side_effect = hup
        lb.bootstrapped_controllers[proxy] = controller
        lb._update_proxy_lists({proxy: 1})
        try:
            lb.trigger_reactive_removal(proxy, "down")
            self.assertTrue(entered.wait(1))
            for _ in range(40):
                lb.trigger_reactive_removal(proxy, "still down")
                lb.trigger_reload(proxy, "packet loss")
            self.assertEqual(lb.get_candidate_proxies(), [])
            controller.signal.assert_called_once_with(lb.Signal.HUP)
        finally:
            release.set()
        deadline = time.monotonic() + 2
        while lb._reloading_proxies and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertFalse(lb._reloading_proxies)
        lb.trigger_reload(proxy, "during cooldown")
        controller.signal.assert_called_once()

    def open_client(self):
        client, server = socket.socketpair()
        client.settimeout(3)
        worker = threading.Thread(target=lb.handle_client_connection, args=(server, "fixture"))
        worker.start()
        self.addCleanup(worker.join, 3)
        self.addCleanup(client.close)
        client.sendall(b"\x05\x01\x00")
        self.assertEqual(lb._recv_exact(client, 2), b"\x05\x00")
        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
        return client, lb._recv_exact(client, 10)[1], worker

    def test_live_streams_survive_reranking_and_failed_connections_release_reservations(self):
        with socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoBackend) as backend:
            backend.daemon_threads = True
            listener = threading.Thread(target=backend.serve_forever, args=(0.02,))
            listener.start()
            try:
                with socket.socket() as refusing:
                    refusing.bind(("127.0.0.1", 0))
                    dead, good = refusing.getsockname(), backend.server_address
                    lb.TOP_N_PROXIES = 1
                    lb._update_proxy_lists({dead: 1, good: 2})
                    clients = [self.open_client() for _ in range(4)]
                    self.assertEqual([status for _, status, _ in clients], [0] * 4)
                    self.assertEqual(lb._in_use, {good: 4})
                    lb._update_proxy_lists({})
                    lb.api_client.pause_all_except.assert_called_with([good[1]])
                    self.assertEqual(self.open_client()[1], 1)
                    for client, _, worker in clients:
                        client.sendall(b"still open")
                        self.assertEqual(lb._recv_exact(client, 10), b"still open")
                        client.close()
                        worker.join(2)
                        self.assertFalse(worker.is_alive())
                    self.assertFalse(lb._in_use)
                    lb._update_proxy_lists({})
                    lb.api_client.pause_all_except.assert_called_with([])
            finally:
                backend.shutdown()
                listener.join(2)

    def test_bootstrap_closes_rejected_and_expired_controllers(self):
        ready, rejected, late = self.proxies[:3]
        ready_controller, late_controller = Mock(), Mock()
        ready_controller.get_circuits.return_value = []
        sockets = [Mock(), Mock(), Mock()]
        pending = {ready, rejected, late}
        with (patch.object(lb.stem.socket, "ControlPort", side_effect=sockets),
              patch.object(lb.stem.connection, "authenticate", side_effect=[None, RuntimeError("rejected"), None]),
              patch.object(lb.stem.control, "Controller", side_effect=[ready_controller, late_controller]) as wrap,
              patch.object(lb, "is_bootstrapped", side_effect=[True, False])):
            self.assertEqual(lb._poll_bootstrap(pending, "fixture"), [ready])
        # Bootstrap alone is insufficient. Pending instances keep running while
        # the first admitted instance is measured.
        self.assertFalse(lb.get_candidate_proxies())
        with patch.object(lb, "check_proxy_download_fixed", return_value=(1, 100)):
            lb._run_full_check_cycle([ready], {}, pending, publish_each=True)
        self.assertEqual(lb.get_candidate_proxies(), [ready])
        lb.api_client.pause_all_except.assert_called_with([ready[1], rejected[1], late[1]])
        lb._retire_unbootstrapped(pending)
        self.assertEqual(lb.bootstrapped_controllers, {ready: ready_controller})
        ready_controller.close.assert_not_called()
        sockets[1].close.assert_called_once()
        self.assertEqual(wrap.call_count, 2)
        late_controller.signal.assert_called_once_with(lb.Signal.SHUTDOWN)
        late_controller.close.assert_called_once()

    def test_emergency_rechecks_observe_cooldown_and_cleanup(self):
        controller = Mock()
        lb.bootstrapped_controllers[self.proxies[0]] = controller
        clock = [0]
        audits = []

        def wait(seconds):
            clock[0] += seconds
            if len(audits) == 3:
                lb._stopping.set()
            return lb._stopping.is_set()

        def arrive(pending, password):
            pending.clear()
            return self.proxies[:1]

        def audit(*args, **kwargs):
            audits.append(clock[0])
            for _ in range(40):
                lb._full_recheck_needed_event.set()

        with (patch.object(lb, "_poll_bootstrap", side_effect=arrive),
              patch.object(lb, "_run_full_check_cycle", side_effect=audit),
              patch.object(lb.time, "monotonic", side_effect=lambda: clock[0]),
              patch.object(lb._stopping, "wait", side_effect=wait)):
            lb.monitor_proxies("fixture")
        self.assertEqual(audits, [60, 60 + lb.MIN_RECHECK_INTERVAL,
                                  60 + 2 * lb.MIN_RECHECK_INTERVAL])
        controller.close.assert_called_once()
        self.assertFalse(lb.bootstrapped_controllers)


if __name__ == "__main__":
    unittest.main()
