import socket
import math
import signal
import sys
from collections import Counter
import select
import threading
import time
import requests
import logging
import argparse
import socks
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import stem
import stem.connection
import stem.control
import stem.socket
import stem.response
from stem import CircStatus, GuardStatus
from stem.control import EventType
from stem import Signal
import statistics
from api_client import ApiClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

# API client for managing Tor instances
api_client = ApiClient()

# --- Shared state and trigger mechanism ---
_shared_state_lock = threading.Lock()
TOP_N_PROXIES = None
CHECK_MODE = None
bootstrapped_controllers = {}
entry_guards = {}
# Master list of ALL healthy proxies, sorted by performance (best first).
_healthy_sorted_proxies = []
# Includes upstream handshakes as well as established streams.
_in_use = Counter()
# Index for round-robin selection. Must be accessed under the lock.
_round_robin_index = 0
# Original list of proxies from arguments remains the same.
_target_proxies = []
# This event is set if the number of healthy proxies drops below N.
_full_recheck_needed_event = threading.Event()
# A DOWN event during an audit takes precedence over a stale success.
_invalidated_during_check = set()
_stopping = threading.Event()
MIN_RECHECK_INTERVAL = 60
# Packet stats
packet_stats_per_proxy = {}
packet_stats_n_packets_threshold = 100
packet_stats_packet_loss_threshold = 0.5
packet_stats_enable_trigger = True
# Reload Trigger
_reloading_proxies = set()
RELOAD_COOLDOWN = 30 * 60  # seconds
_last_reload_time = {}
# Startup Config
STARTUP_COOLDOWN = 30 * 60 # seconds

# Max concurrent client connections to prevent thread exhaustion
MAX_CONCURRENT_CLIENTS = 500
_client_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_CLIENTS)

# --- CONSTANTS for health checks ---
PING_MONITORING_INTERVAL = 1 * 60 * 60
DOWNLOAD_MONITORING_INTERVAL = 12 * 60 * 60

def _recv_exact(sock, num_bytes):
    """Helper to receive exactly num_bytes from a socket."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def check_proxy_ping(proxy_host, proxy_port, num_rounds=10, requests_per_round=10):
    """Measures proxy performance by running multiple rounds of parallel requests."""
    TEST_URL = "http://connectivitycheck.gstatic.com/generate_204"
    HEALTH_CHECK_TIMEOUT = 5 # seconds
    HEALTH_CHECK_TIMEOUT_PENALTY = 99999

    total_requests = num_rounds * requests_per_round
    logging.info(
        f"--- Starting Performance Test for {proxy_host}:{proxy_port} ---\n"
        f"Configuration: {num_rounds} rounds, {requests_per_round} parallel requests per round."
    )
    proxy_url = f'socks5h://{proxy_host}:{proxy_port}'
    proxies = {'http': proxy_url, 'https': proxy_url}
    with requests.Session() as session:
        def _make_single_request():
            try:
                start_time = time.monotonic()
                with session.get(TEST_URL, proxies=proxies, timeout=HEALTH_CHECK_TIMEOUT) as response:
                    if response.status_code == 204:
                        return time.monotonic() - start_time
            except requests.exceptions.RequestException:
                pass
            return HEALTH_CHECK_TIMEOUT_PENALTY

        with ThreadPoolExecutor(max_workers=requests_per_round) as executor:
            futures = [executor.submit(_make_single_request) for _ in range(total_requests)]
            all_latencies = [f.result() for f in futures]

    overall_avg_latency = statistics.median(all_latencies)
    success_count = sum(1 for lat in all_latencies if lat < HEALTH_CHECK_TIMEOUT_PENALTY)
    success_rate = (success_count / total_requests) * 100

    logging.info(f"--- Performance Test Summary for {proxy_host}:{proxy_port} ---")
    logging.info(f"Successful requests: {success_count}/{total_requests} ({success_rate:.1f}%)")
    logging.info(f"Overall avg latency: {overall_avg_latency:.4f}s (includes penalties)")
    logging.info("---------------------------------")
    overall_avg_latency = overall_avg_latency if overall_avg_latency != HEALTH_CHECK_TIMEOUT_PENALTY else None
    return overall_avg_latency, success_rate

class TotalTimeout(Exception):
    """Custom exception for total download timeout."""
    pass

def check_proxy_download_full(proxy_host, proxy_port, num_downloads=1, total_timeout=200):
    """
    Measures the median time it takes to download a test file via a proxy,
    enforcing a total time limit for the download.
    """
    DOWNLOAD_URL = "https://proof.ovh.net/files/10Mb.dat"
    # A penalty value significantly higher than any possible timeout
    DOWNLOAD_TIMEOUT_PENALTY = 99999
    # A reasonable connect/read timeout for establishing the connection and getting the first byte
    # This prevents the initial request from hanging indefinitely.
    INITIAL_REQUEST_TIMEOUT = (15, 30) # (connect_timeout, read_timeout)

    logging.info(f"--- Starting Download Time Test for {proxy_host}:{proxy_port} (Total Timeout: {total_timeout}s) ---")
    session = requests.Session()
    session.proxies = {
        'http': f'socks5h://{proxy_host}:{proxy_port}',
        'httpss': f'socks5h://{proxy_host}:{proxy_port}'
    }
    all_durations = []
    
    for i in range(num_downloads):
        start_time = time.time()
        try:
            # Use stream=True to avoid downloading the entire content at once.
            # This lets us control the download process.
            with session.get(DOWNLOAD_URL, stream=True, timeout=INITIAL_REQUEST_TIMEOUT) as response:
                response.raise_for_status()
                # We will write to a null-like object to consume the download content
                # without saving it to memory or disk.
                # In Python 3, io.BytesIO() is a good in-memory buffer.
                # For very large files, you might use open(os.devnull, 'wb')
                from io import BytesIO
                downloaded_content = BytesIO()
                for chunk in response.iter_content(chunk_size=8192):
                    # Check the total elapsed time on each chunk
                    if time.time() - start_time > total_timeout:
                        raise TotalTimeout(f"Download exceeded total timeout of {total_timeout} seconds.")  
                    downloaded_content.write(chunk)
            # If the loop completes without raising TotalTimeout, the download was successful and within the time limit.
            duration = time.time() - start_time
            all_durations.append(duration)
            logging.info(f"Download {i+1}/{num_downloads} success in {duration:.2f}s")
        except (requests.exceptions.RequestException, TotalTimeout) as e:
            # Catch connection errors, bad status codes, AND our custom total timeout.
            logging.warning(f"Download {i+1}/{num_downloads} failed: {e}")
            all_durations.append(DOWNLOAD_TIMEOUT_PENALTY)
            
    overall_median_time = statistics.median(all_durations) if all_durations else DOWNLOAD_TIMEOUT_PENALTY
    success_count = sum(1 for lat in all_durations if lat < DOWNLOAD_TIMEOUT_PENALTY)
    success_rate = (success_count / num_downloads) * 100

    logging.info(f"--- Download Test Summary for {proxy_host}:{proxy_port}: Median time {overall_median_time:.2f}s ---")
    overall_median_time = overall_median_time if overall_median_time < DOWNLOAD_TIMEOUT_PENALTY else None
    return overall_median_time, success_rate

def check_proxy_download_fixed(proxy_host, proxy_port, num_tests=1, test_duration=10):
    """
    Measures the median download speed (bytes/sec) through a proxy over a fixed time period.

    Args:
        proxy_host (str): The hostname or IP address of the proxy server.
        proxy_port (int): The port number of the proxy server.
        num_tests (int): The number of times to run the test to calculate a median.
        test_duration (int): The duration in seconds for each download test.

    Returns:
        tuple: A tuple containing:
            - median_speed_bps (float): The median download speed in bytes per second. 
                                        Returns 0.0 if all tests fail.
            - success_rate (float): The percentage of successful test runs.
    """
    # Use a larger file to ensure the download doesn't finish before the test duration
    # for most internet speeds.
    DOWNLOAD_URL = "https://proof.ovh.net/files/100Mb.dat"
    
    # A reasonable connect/read timeout for establishing the connection and getting the first byte.
    # This prevents the initial request from hanging indefinitely.
    INITIAL_REQUEST_TIMEOUT = (15, 30) # (connect_timeout, read_timeout)

    logging.info(f"--- Starting Download Speed Test for {proxy_host}:{proxy_port} ({num_tests} tests, {test_duration}s each) ---")
    
    proxy_url = f'socks5h://{proxy_host}:{proxy_port}'
    proxies = {'http': proxy_url, 'https': proxy_url}
    all_speeds = []

    for i in range(num_tests):
        total_bytes_downloaded = 0
        start_time = time.monotonic()
        
        try:
            # Use stream=True to control the download process chunk by chunk.
            with requests.Session() as session, session.get(
                DOWNLOAD_URL, proxies=proxies, stream=True, timeout=INITIAL_REQUEST_TIMEOUT
            ) as response:
                response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
                
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        # The download finished before the timer ran out
                        break
                        
                    total_bytes_downloaded += len(chunk)
                    
                    # Check if the test duration has been reached
                    if time.monotonic() - start_time >= test_duration:
                        break
            
            # The download loop finished (either by timeout or completion)
            actual_duration = time.monotonic() - start_time
            
            # Calculate speed in bytes per second. Avoid division by zero.
            speed_bps = (total_bytes_downloaded / actual_duration) if actual_duration > 0 else 0
            all_speeds.append(speed_bps)

            # Log results in human-readable format (MB and MB/s)
            downloaded_mb = total_bytes_downloaded / (1024 * 1024)
            speed_mbps = speed_bps / (1024 * 1024)
            logging.info(f"Test {i+1}/{num_tests} success: Downloaded {downloaded_mb:.2f} MB in {actual_duration:.2f}s (Speed: {speed_mbps:.2f} MB/s)")

        except requests.exceptions.RequestException as e:
            # Catch connection errors, timeouts, etc.
            logging.warning(f"Test {i+1}/{num_tests} failed: {e}")
            # A failed test has a speed of 0 bytes/sec
            all_speeds.append(0.0)
            
    # --- Final calculations ---
    median_speed_bps = statistics.median(all_speeds) if all_speeds else 0.0
    
    # A test is considered successful if its speed was greater than 0
    success_count = sum(1 for speed in all_speeds if speed > 0)
    success_rate = (success_count / num_tests) * 100 if num_tests > 0 else 0

    median_speed_mbps = median_speed_bps / (1024 * 1024)
    logging.info(f"--- Speed Test Summary for {proxy_host}:{proxy_port}: Median Speed {median_speed_mbps:.2f} MB/s | Success Rate: {success_rate:.1f}% ---")
    
    if median_speed_bps <= 0:
        return None, 0.0

    median_speed_bps = 1 / median_speed_bps # Inverse It For Ascending Sort
    return median_speed_bps, success_rate

def get_control_port(socks_port):
    """Derives the Tor control port from a SOCKS port."""
    return int(socks_port) + 900

def trigger_reactive_removal(proxy_tuple, reason):
    """Withdraw the endpoint for new connections until it passes another check."""
    with _shared_state_lock:
        _invalidated_during_check.add(proxy_tuple)
        if proxy_tuple not in _healthy_sorted_proxies:
            return
        logging.warning("Removing %s from rotation: %s", proxy_tuple, reason)
        _healthy_sorted_proxies.remove(proxy_tuple)
        if len(_healthy_sorted_proxies) < TOP_N_PROXIES:
            _full_recheck_needed_event.set()

    trigger_reload(proxy_tuple, reason)


def trigger_reload(proxy_tuple, reason):
    """Share one in-flight HUP and one cooldown across all notification sources."""
    with _shared_state_lock:
        controller_to_reload = bootstrapped_controllers.get(proxy_tuple)
        now = time.monotonic()
        if (controller_to_reload is None or proxy_tuple in _reloading_proxies
                or now - _last_reload_time.get(proxy_tuple, -math.inf) < RELOAD_COOLDOWN):
            return
        _reloading_proxies.add(proxy_tuple)
        _last_reload_time[proxy_tuple] = now
        packet_stats_per_proxy[proxy_tuple] = {"Successful": 0, "Failed": 0}

    def _async_hup(ctrl, pt):
        try:
            ctrl.signal(Signal.HUP)
            logging.info("HUP signal sent to Tor for %s.", pt)
        except Exception:
            logging.exception("Failed to send HUP signal to Tor for %s.", pt)
        finally:
            with _shared_state_lock:
                _reloading_proxies.discard(pt)

    try:
        threading.Thread(target=_async_hup, args=(controller_to_reload, proxy_tuple), daemon=True).start()
    except RuntimeError:
        with _shared_state_lock:
            _reloading_proxies.discard(proxy_tuple)
        logging.exception("Could not start reload for %s (%s)", proxy_tuple, reason)


def _record_proxy_result(proxy_tuple, success, reason="SOCKS FAILURE"):
    """Records packet stats and reactively triggers demotion if error rate is too high."""
    if not proxy_tuple:
        return
    should_trigger = False
    with _shared_state_lock:
        if proxy_tuple not in packet_stats_per_proxy:
            packet_stats_per_proxy[proxy_tuple] = {"Successful": 0, "Failed": 0}
        if success:
            packet_stats_per_proxy[proxy_tuple]["Successful"] += 1
        else:
            packet_stats_per_proxy[proxy_tuple]["Failed"] += 1
            total = packet_stats_per_proxy[proxy_tuple]["Successful"] + packet_stats_per_proxy[proxy_tuple]["Failed"]
            if total > packet_stats_n_packets_threshold:
                if packet_stats_per_proxy[proxy_tuple]["Failed"] / total > packet_stats_packet_loss_threshold:
                    should_trigger = True

    if should_trigger and packet_stats_enable_trigger:
        trigger_reload(proxy_tuple, reason)

def _publish_ranking(scores):
    """Publish probe results and return the ports needed by live connections."""
    global _healthy_sorted_proxies, _round_robin_index
    ranked = sorted(scores, key=scores.get)
    with _shared_state_lock:
        healthy = [p for p in ranked if p not in _invalidated_during_check]
        if healthy[:TOP_N_PROXIES] != _healthy_sorted_proxies[:TOP_N_PROXIES]:
            _round_robin_index = 0
        _healthy_sorted_proxies = healthy
        return {port for _, port in set(healthy).union(_in_use)}


def _update_proxy_lists(scores, pending=()):
    keep_running = _publish_ranking(scores)
    # Pending Tor instances need CPU to bootstrap. A retired endpoint with a
    # live stream stays runnable until a subsequent audit observes it drained.
    keep_running.update(port for _, port in pending)
    api_client.pause_all_except(sorted(keep_running))
    with _shared_state_lock:
        if not _healthy_sorted_proxies:
            _full_recheck_needed_event.set()


def _run_full_check_cycle(targets=None, scores=None, pending=(), publish_each=False):
    """Probe the given backends. Keep prior scores when admitting new arrivals."""
    if targets is None:
        targets = _target_proxies
    if scores is None:
        scores = {}
    with _shared_state_lock:
        # A partial publication must never resurrect a withdrawn backend
        # using its score from before the notification.
        for proxy in _invalidated_during_check.intersection(targets):
            scores.pop(proxy, None)
        _invalidated_during_check.difference_update(targets)
    api_client.resume_all()
    check_func = check_proxy_ping if CHECK_MODE == 0 else check_proxy_download_fixed
    for proxy in targets:
        if _stopping.is_set():
            return
        scores.pop(proxy, None)
        try:
            score, success_rate = check_func(*proxy)
            if score is not None and math.isfinite(score) and success_rate > 0:
                scores[proxy] = score
                # Serve the first verified arrival while its peers are checked.
                if publish_each:
                    _publish_ranking(scores)
        except Exception as e:
            logging.warning("Health check failed for %s: %s", proxy, e)
    if _stopping.is_set():
        return
    # Query responsive controllers before this audit can SIGSTOP any of them.
    store_entry_guards({p: bootstrapped_controllers[p] for p in targets
                        if p in scores and p in bootstrapped_controllers})
    _update_proxy_lists(scores, pending)


def store_entry_guards(bootstrapped_controllers):
    for proxy_tuple, controller in bootstrapped_controllers.items():
        guards = []
        try:
            for circ in sorted(controller.get_circuits()):
                if circ.status != CircStatus.BUILT:
                    continue
                guard_fingerprint = circ.path[0][0] # [First Node Of Circuit][Fingerprint]
                guards.append(guard_fingerprint)
            if guards:
                most_frequent_guard = max(set(guards), key=guards.count)
                entry_guards[proxy_tuple] = most_frequent_guard
        except Exception as e:
            logging.warning(f"Error fetching guards for {proxy_tuple}: {e}")

# --- FIXED & CORRECT EVENT HANDLERS ---
def generic_guard_handler(proxy_tuple, event):
    """Handles GUARD events. This logic was correct."""
    if event.status in [GuardStatus.DOWN, GuardStatus.BAD]:
        if event.endpoint_fingerprint == entry_guards.get(proxy_tuple):
            logging.warning(f"Proxy {proxy_tuple} reported guard status: {event.status}. Triggering removal.")
            trigger_reactive_removal(proxy_tuple, f"GUARD {event.status}")

def generic_status_handler(proxy_tuple, event):
    """
    FIXED: Handles only STATUS_CLIENT events.
    Reacts directly to the event's content, avoiding a redundant getinfo call.
    """
    if event.action == "BOOTSTRAP":
        progress = int(event.arguments.get('PROGRESS', -1))
        tag = event.arguments.get('TAG', 'unknown')

        # Any bootstrap event that isn't the final "done" one implies it's not ready.
        if tag != 'done' or progress < 100:
            logging.info(f"Proxy {proxy_tuple} is (re)bootstrapping (progress {progress}%, tag: {tag}). Removing from active pool.")
            trigger_reactive_removal(proxy_tuple, f"BOOTSTRAP RESTART (progress {progress}%)")

def network_liveness_handler(proxy_tuple, event):
    """
    NEW: Handles only NETWORK_LIVENESS events. This is a separate event type
    from STATUS_CLIENT and needs its own handler.
    """
    # As per the stem unittests, the status is on the event object directly.
    if event.status == "DOWN":
        logging.warning(f"Proxy {proxy_tuple} reported network is DOWN. Triggering removal.")
        trigger_reactive_removal(proxy_tuple, "NETWORK LIVENESS DOWN")

def monitor_proxies(control_password):
    """A single monitor polls bootstrap and serializes scheduled and reactive checks."""
    pending = set(_target_proxies)
    ready = []
    scores = {}
    interval = PING_MONITORING_INTERVAL if CHECK_MODE == 0 else DOWNLOAD_MONITORING_INTERVAL
    try:
        if _stopping.wait(60):
            return
        # An earlier balancer may have exited with some backends paused.
        api_client.resume_all()
        deadline = time.monotonic() + STARTUP_COOLDOWN
        next_poll = retry_at = 0
        periodic_at = math.inf
        while (pending or ready) and not _stopping.is_set():
            arrivals = []
            if pending and time.monotonic() >= next_poll:
                arrivals = _poll_bootstrap(pending, control_password)
                ready.extend(arrivals)
                if time.monotonic() >= deadline:
                    _retire_unbootstrapped(pending)
                    pending.clear()
                next_poll = time.monotonic() + 10

            now = time.monotonic()
            requested = _full_recheck_needed_event.is_set()
            full = now >= periodic_at or (requested and now >= retry_at)
            if arrivals or (ready and full):
                if full:
                    _full_recheck_needed_event.clear()
                _run_full_check_cycle(ready if full else arrivals, scores, pending,
                                      publish_each=bool(arrivals))
                retry_at = time.monotonic() + MIN_RECHECK_INTERVAL
                periodic_at = time.monotonic() + interval

            if _stopping.is_set() or (not pending and not ready):
                break
            wake_at = min(next_poll if pending else math.inf, periodic_at)
            if _full_recheck_needed_event.is_set():
                # An already set Event would return immediately. Honor a quiet
                # period after each audit even under continuous notifications.
                if ready:
                    wake_at = min(wake_at, retry_at)
                _stopping.wait(max(0, wake_at - time.monotonic()))
            else:
                _full_recheck_needed_event.wait(max(0, wake_at - time.monotonic()))
    finally:
        api_client.resume_all()
        with _shared_state_lock:
            controllers = list(bootstrapped_controllers.values())
            bootstrapped_controllers.clear()
        for controller in controllers:
            controller.close()


def get_candidate_proxies():
    """Rotate the first choice among the best N, then try healthy fallbacks."""
    global _round_robin_index
    with _shared_state_lock:
        pool = _healthy_sorted_proxies
        n = min(TOP_N_PROXIES, len(pool))
        if not n:
            _full_recheck_needed_event.set()
            return []
        idx = _round_robin_index % n
        _round_robin_index = (idx + 1) % n
        return pool[idx:n] + pool[:idx] + pool[n:]


def _release_proxy(proxy):
    with _shared_state_lock:
        _in_use[proxy] -= 1
        if not _in_use[proxy]:
            del _in_use[proxy]


def select_proxy_round_robin():
    """Selects a proxy from the top N list using a round-robin strategy."""
    candidates = get_candidate_proxies()
    return candidates[0] if candidates else None

def handle_client_connection(client_socket, client_address):
    """Handles a single client connection, forwarding it through a selected SOCKS5 proxy."""
    logging.info(f"Accepted connection from {client_address}")
    proxy_socket = None
    reserved_proxy = None

    try:
        # Enforce connection timeout on client socket to avoid hanging threads
        client_socket.settimeout(10)

        # 2. SOCKS5 handshake with the client (Version identifier/method selection)
        version_id_msg = _recv_exact(client_socket, 2)
        if not version_id_msg or len(version_id_msg) < 2:
            logging.warning(f"Client {client_address} sent incomplete version/nmethods. Closing.")
            client_socket.close(); return

        sock_version, nmethods = version_id_msg[0], version_id_msg[1]
        if sock_version != 0x05:
            logging.error(f"Unsupported SOCKS version from {client_address}: {sock_version}"); client_socket.close(); return

        client_methods = _recv_exact(client_socket, nmethods)
        if not client_methods or 0x00 not in client_methods:
            logging.error(f"Client {client_address} does not support NO AUTH method. Closing.")
            client_socket.sendall(b'\x05\xFF'); client_socket.close(); return

        client_socket.sendall(b'\x05\x00') # Select NO AUTH method

        # 3. SOCKS5 client request (get destination from client)
        client_req_header = _recv_exact(client_socket, 4)
        if not client_req_header or len(client_req_header) < 4:
            logging.warning(f"Client {client_address} sent incomplete request header. Closing."); client_socket.close(); return

        req_ver, req_cmd, _, req_atyp = client_req_header
        if req_ver != 0x05 or req_cmd != 0x01: # Check for SOCKSv5 CONNECT
            logging.error(f"Unsupported request from {client_address}: VER={req_ver}, CMD={req_cmd}. Sending error.")
            client_socket.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00'); client_socket.close(); return

        if req_atyp == 0x01: # IPv4
            dst_addr_bytes = _recv_exact(client_socket, 4)
        elif req_atyp == 0x03: # Domain name
            domain_len_byte = _recv_exact(client_socket, 1)
            if not domain_len_byte:
                logging.warning(f"Client {client_address} sent incomplete domain length. Closing."); client_socket.close(); return
            domain_len = domain_len_byte[0]
            domain_bytes = _recv_exact(client_socket, domain_len)
            if not domain_bytes:
                logging.warning(f"Client {client_address} sent incomplete domain body. Closing."); client_socket.close(); return
            dst_addr_bytes = domain_len_byte + domain_bytes
        elif req_atyp == 0x04: # IPv6
            dst_addr_bytes = _recv_exact(client_socket, 16)
        else:
            logging.error(f"Unsupported ATYP from {client_address}: {req_atyp}. Sending error.")
            client_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00'); client_socket.close(); return

        dst_port_bytes = _recv_exact(client_socket, 2)
        if not dst_addr_bytes or not dst_port_bytes or len(dst_addr_bytes) < 1 or len(dst_port_bytes) < 2:
            logging.warning(f"Client {client_address} sent incomplete address/port. Closing."); client_socket.close(); return

        upstream_request = client_req_header + dst_addr_bytes + dst_port_bytes

        # --- Use the round-robin selection function ---
        candidate_proxies = get_candidate_proxies()
        if not candidate_proxies:
            logging.error(f"No healthy upstream SOCKS proxy available for {client_address}. Closing connection.")
            client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            client_socket.close()
            return

        connected_proxy = None

        for upstream_proxy in candidate_proxies:
            # Revalidate the snapshot and reserve atomically with publication:
            # a concurrent audit must keep this Tor running through the relay.
            with _shared_state_lock:
                if upstream_proxy not in _healthy_sorted_proxies:
                    continue
                _in_use[upstream_proxy] += 1
                reserved_proxy = upstream_proxy
            upstream_host, upstream_port = upstream_proxy
            logging.info(f"Selected upstream SOCKS proxy {upstream_host}:{upstream_port} for {client_address} via round-robin")
            temp_proxy_socket = None
            try:
                # 4. Connect and handshake with the upstream SOCKS proxy
                logging.debug(f"Connecting to upstream proxy {upstream_host}:{upstream_port}")
                temp_proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_proxy_socket.settimeout(10)
                temp_proxy_socket.connect((upstream_host, upstream_port))

                temp_proxy_socket.sendall(b'\x05\x01\x00')
                server_choice = _recv_exact(temp_proxy_socket, 2)
                if not server_choice or len(server_choice) < 2 or server_choice[0] != 0x05 or server_choice[1] != 0x00:
                    raise socks.SOCKS5Error(f"Upstream proxy {upstream_host}:{upstream_port} did not accept NO AUTH method. Reply: {server_choice.hex() if server_choice else 'None'}")
                logging.debug(f"Handshake with upstream proxy {upstream_host}:{upstream_port} successful.")

                # 5. Forward client's request to upstream proxy
                temp_proxy_socket.sendall(upstream_request)

                # 6. Relay reply from upstream proxy back to client
                proxy_reply_header = _recv_exact(temp_proxy_socket, 4)
                if not proxy_reply_header or len(proxy_reply_header) < 4:
                    raise ConnectionAbortedError("Upstream proxy closed connection before sending reply header.")

                if proxy_reply_header[1] != 0x00:
                    raise socks.SOCKS5Error(f"Upstream proxy {upstream_host}:{upstream_port} failed request for {client_address}. REP: {proxy_reply_header[1]}.")

                reply_atyp = proxy_reply_header[3]
                if reply_atyp == 0x01: # IPv4
                    bnd_data = _recv_exact(temp_proxy_socket, 6)
                elif reply_atyp == 0x04: # IPv6
                    bnd_data = _recv_exact(temp_proxy_socket, 18)
                elif reply_atyp == 0x03: # Domain name
                    len_byte = _recv_exact(temp_proxy_socket, 1)
                    if not len_byte:
                        raise ConnectionAbortedError("Failed to read bound domain length from upstream proxy.")
                    bnd_len = len_byte[0]
                    rest = _recv_exact(temp_proxy_socket, bnd_len + 2)
                    if not rest:
                        raise ConnectionAbortedError("Failed to read bound domain/port from upstream proxy.")
                    bnd_data = len_byte + rest
                else:
                    raise socks.SOCKS5Error(f"Unsupported ATYP from upstream proxy: {reply_atyp}")

                if not bnd_data:
                    raise ConnectionAbortedError("Failed to read bound address/port from upstream proxy.")

                connected_proxy = upstream_proxy
                proxy_socket = temp_proxy_socket
                break

            except (socket.error, socks.SOCKS5Error, BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
                logging.warning(f"Upstream proxy {upstream_host}:{upstream_port} failed for {client_address}: {e}. Trying next proxy in list...")
                if temp_proxy_socket:
                    try:
                        temp_proxy_socket.close()
                    except Exception:
                        pass
                _release_proxy(upstream_proxy)
                reserved_proxy = None
                _record_proxy_result(upstream_proxy, success=False)
                continue

        if not connected_proxy or not proxy_socket:
            _full_recheck_needed_event.set()
            logging.error(f"All candidate upstream proxies failed for {client_address}.")
            if not client_socket._closed:
                try:
                    client_socket.sendall(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                except socket.error:
                    pass
            return

        client_socket.sendall(proxy_reply_header + bnd_data)

        # 7. Relay data
        # Success
        upstream_host, upstream_port = connected_proxy
        logging.info(f"SOCKS connection established for {client_address} via {upstream_host}:{upstream_port}. Relaying data.")
        relay_data(client_socket, proxy_socket, client_address)
        _record_proxy_result(connected_proxy, success=True)

    except (socket.error, socks.SOCKS5Error, BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
        logging.error(f"Error during SOCKS relay for {client_address}: {e}")
    finally:
        if client_socket and not client_socket._closed:
            client_socket.close()
        if proxy_socket and not proxy_socket._closed:
            proxy_socket.close()
        if reserved_proxy is not None:
            _release_proxy(reserved_proxy)
        logging.info(f"Closed connection for {client_address}")

def relay_data(sock1, sock2, client_address):
    """
    Relays data between two sockets until one closes or an error occurs.
    Single-threaded implementation using select to prevent thread exhaustion.
    """
    sockets = [sock1, sock2]
    sock1.settimeout(60)
    sock2.settimeout(60)

    try:
        while True:
            rlist, _, xlist = select.select(sockets, [], sockets, 60)
            if xlist or not rlist:
                break
            for s in rlist:
                other = sock2 if s is sock1 else sock1
                data = s.recv(8192)
                if not data:
                    return
                other.sendall(data)
    except (socket.error, BrokenPipeError, ConnectionResetError) as e:
        logging.debug(f"Socket error during relay for {client_address}: {e}")
    finally:
        for s in sockets:
            if not s._closed:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except socket.error:
                    pass
                finally:
                    s.close()
        logging.debug(f"Relay finished for {client_address}")

def start_server(listen_host, listen_port):
    """Starts the SOCKS5 proxy server and listens for connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((listen_host, listen_port))
        server_socket.listen(128)
        logging.info(f"Custom LB SOCKS5 Proxy listening on {listen_host}:{listen_port}")
        logging.info(f"Strategy: Round-robin top {TOP_N_PROXIES} proxies.")
    except OSError:
        server_socket.close()
        raise

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            # Prevent 'can't start new thread' by capping total concurrent threads
            if not _client_semaphore.acquire(blocking=False):
                logging.warning(f"Connection limit reached ({MAX_CONCURRENT_CLIENTS}). Dropping {client_address}")
                client_socket.close()
                continue

            def _worker_wrapper(cs, ca):
                try:
                    handle_client_connection(cs, ca)
                finally:
                    _client_semaphore.release()

            client_thread = threading.Thread(target=_worker_wrapper, args=(client_socket, client_address))
            client_thread.daemon = True
            try:
                client_thread.start()
            except RuntimeError:
                client_socket.close()
                _client_semaphore.release()
                logging.exception("Could not start SOCKS worker")
        except KeyboardInterrupt:
            logging.info("Server shutting down on KeyboardInterrupt.")
            break
        except socket.error as e:
            logging.error(f"Socket error during accept: {e}")
            time.sleep(0.1)

    server_socket.close()
    logging.info("Server stopped.")

def is_bootstrapped(controller):
    """Checks if a Tor instance is fully bootstrapped by querying its control port."""
    try:
        response = controller.get_info("status/bootstrap-phase")
        # Use stem's response parser, similar to the example code.
        status = stem.response.ControlLine(response)
        while not status.is_empty():
            if status.is_next_mapping():
                key, value = status.pop_mapping(quoted=status.is_next_quoted())
                if key == "PROGRESS" and int(value) == 100:
                    return True
            else:
                # Discard other parts of the line we don't care about.
                status.pop(quoted=status.is_next_quoted())
    except (stem.InvalidResponse, ValueError) as e:
        logging.warning("Invalid bootstrap status: %s", e)
    except stem.SocketError:
        # Re-raise socket errors to be handled by the caller.
        raise
    except Exception as e:
        logging.warning("Could not query bootstrap status: %s", e)
    return False


def _connect_controller(proxy, password):
    # Stem may reconnect the control socket on an authentication rejection.
    # Authenticate before constructing a Controller and its two worker threads.
    host, port = proxy
    control_socket = stem.socket.ControlPort(host, get_control_port(port))
    try:
        stem.connection.authenticate(control_socket, password=password)
        return stem.control.Controller(control_socket, is_authenticated=True)
    except BaseException:
        control_socket.close()
        raise


def _poll_bootstrap(pending, control_password):
    """Keep at most one authenticated controller per endpoint across polls."""
    arrivals = []
    for proxy in sorted(pending):
        if _stopping.is_set():
            break
        controller = bootstrapped_controllers.get(proxy)
        try:
            if controller is not None and not controller.is_alive():
                bootstrapped_controllers.pop(proxy).close()
                controller = None
            if controller is None:
                controller = _connect_controller(proxy, control_password)
                bootstrapped_controllers[proxy] = controller
            if not is_bootstrapped(controller):
                continue
        except Exception as e:
            bootstrapped_controllers.pop(proxy, None)
            if controller is not None:
                controller.close()
            logging.warning("Bootstrap check failed for %s: %s", proxy, e)
            continue

        pending.remove(proxy)
        arrivals.append(proxy)
        # Register before the first health audit can pause this process.
        try:
            controller.add_event_listener(partial(generic_guard_handler, proxy), EventType.GUARD)
            controller.add_event_listener(partial(generic_status_handler, proxy), EventType.STATUS_CLIENT)
            controller.add_event_listener(partial(network_liveness_handler, proxy), EventType.NETWORK_LIVENESS)
        except Exception as e:
            logging.warning("Failed to add event listeners for %s: %s", proxy, e)
    return arrivals


def _retire_unbootstrapped(pending):
    # Preserve the startup grace period and shutdown policy for instances that
    # never reach 100%. Every admitted endpoint remains eligible for rechecks.
    for proxy in pending:
        controller = bootstrapped_controllers.pop(proxy, None)
        if controller is not None:
            try:
                controller.signal(Signal.SHUTDOWN)
            except stem.ControllerError as e:
                logging.warning("Could not shut down %s: %s", proxy, e)
            finally:
                controller.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom SOCKS5 Load Balancer for Tor with advanced health checks.")
    parser.add_argument("--listen-host", type=str, required=True, help="Host to listen on")
    parser.add_argument("--listen-port", type=int, required=True, help="Port to listen on")
    parser.add_argument("--tor-proxies", type=str, required=True, help="Comma-separated list of Tor SOCKS5 proxies")
    parser.add_argument("--top-n-proxies", type=int, required=True, help="Round-robin over the Top N fastest proxies.")
    parser.add_argument("--check-mode", type=int, required=True, choices=[0, 1], help="0 = Ping Check, 1 = Download Check")
    parser.add_argument("--tor-control-password", type=str, default="", help="Password for the Tor control ports. Default is empty for no auth or cookie auth.")

    args = parser.parse_args()

    try:
        proxies_list = []
        for proxy_str in args.tor_proxies.split(','):
            if not proxy_str.strip():
                continue
            host, port_str = proxy_str.strip().split(':')
            proxies_list.append((host, int(port_str)))
        _target_proxies = proxies_list
        if not _target_proxies:
            raise ValueError("No valid proxies were provided.")
        logging.info(f"Target Tor SOCKS proxies: {_target_proxies}")
    except ValueError as e:
        logging.error(f"Invalid format for --tor-proxies: {args.tor_proxies}. Error: {e}. Exiting.")
        exit(1)
    
    for proxy in _target_proxies:
        packet_stats_per_proxy[proxy] = {"Successful": 0, "Failed": 0}

    if args.top_n_proxies < 1:
        parser.error("--top-n-proxies must be positive")
    TOP_N_PROXIES = args.top_n_proxies
    if TOP_N_PROXIES > len(_target_proxies):
        logging.warning(f"--top-n-proxies ({TOP_N_PROXIES}) > total proxies ({len(_target_proxies)}). Using {len(_target_proxies)}.")
        TOP_N_PROXIES = len(_target_proxies)

    CHECK_MODE = args.check_mode

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    monitor_thread = threading.Thread(target=monitor_proxies, args=(args.tor_control_password,), daemon=True)
    monitor_thread.start()

    try:
        start_server(args.listen_host, args.listen_port)
    finally:
        _stopping.set()
        _full_recheck_needed_event.set()
        monitor_thread.join(timeout=5)
        if monitor_thread.is_alive():
            # A pending probe can outlast shutdown. Release paused Tor processes
            # before this process and its daemon threads exit.
            api_client.resume_all()
        logging.info("Custom LB shutting down.")
