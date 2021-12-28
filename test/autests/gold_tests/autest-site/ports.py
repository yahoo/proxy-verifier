'''
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import socket
import subprocess
import os
import platform

import hosts.output as host

try:
    import queue as Queue
except ImportError:
    import Queue

g_ports = None  # ports we can use


class PortQueueSelectionError(Exception):
    """
    An exception for when there are problems selecting a port from the port
    queue.
    """
    pass


def PortOpen(port, address=None):
    """
    Detect whether the port is open, that is a socket is currently using that port.

    Open ports are currently in use by an open socket and are therefore not available
    for a server to listen on them.

    Returns:
        True if there is a connection currently listening on the port, False if
        there is no server listening on the port currently.
    """
    ret = True
    if address is None:
        address = "localhost"

    address = (address, port)

    try:
        # Try to connect on that port. If we can connect on it, then someone is
        # listening on that port and therefore the port is open and not usable
        # by another application.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(address)
            # Bind succeeded.
            host.WriteDebug(
                'PortOpen',
                f"Bind on port {port} succeeded, the port is closed "
                "(no application is listening on it) "
                "and thus a future connection can use it")
            ret = False

    except socket.error:
        host.WriteDebug(
            'PortOpen',
            f"socket error binding on port {port}. "
            "Assume a future connection cannot use it")
    except socket.timeout:
        host.WriteDebug(
            'PortOpen',
            f"Timeout error binding on port {port}. "
            "Assume a future connection cannot use it")

    return ret


def _get_available_port(queue):
    """
    Get the next available port from the port queue and return it.

    Since there can be a delay between when the queue is populated and when the
    port is requested, this checks the next port in the queue to see whether it
    is still not open. If it isn't, it is dropped from the queue and the next
    one is inspected. This process continues until either an available port is
    found, or, if the queue is exhausted, PortQueueSelectionError is raised.

    Returns:
        An available (i.e., non-open) port.

    Throws:
        PortQueueSelectionError if the port queue is exhausted.
    """

    if queue.qsize() == 0:
        host.WriteWarning("Port queue is empty.")
        raise PortQueueSelectionError(
            "Could not get a valid port because the queue is empty")

    port = queue.get()
    while PortOpen(port):
        host.WriteDebug(
            '_get_available_port',
            f"Port was open but now is used: {port}")
        if queue.qsize() == 0:
            host.WriteWarning("Port queue is empty.")
            raise PortQueueSelectionError(
                "Could not get a valid port because the queue is empty")
        port = queue.get()
    return port


def _setup_port_queue(amount=1000):
    """
    Build up the set of ports that the OS in theory will not use.
    """
    global g_ports
    if g_ports is None:
        host.WriteDebug(
            '_setup_port_queue',
            "Populating the port queue.")
        g_ports = Queue.Queue()
    else:
        # The queue has already been populated.
        host.WriteDebug(
            '_setup_port_queue',
            f"Queue was previously populated. Queue size: {g_ports.qsize()}")
        return
    try:
        # Use sysctl to find the range of ports that the OS publishes it uses.
        # some docker setups don't have sbin setup correctly
        new_env = os.environ.copy()
        new_env['PATH'] = "/sbin:/usr/sbin:" + new_env['PATH']
        if 'Darwin' == platform.system():
            dmin = subprocess.check_output(
                ["sysctl", "net.inet.ip.portrange.first"],
                env=new_env
            ).decode().split(":")[1].split()[0]
            dmax = subprocess.check_output(
                ["sysctl", "net.inet.ip.portrange.last"],
                env=new_env
            ).decode().split(":")[1].split()[0]
        else:
            dmin, dmax = subprocess.check_output(
                ["sysctl", "net.ipv4.ip_local_port_range"],
                env=new_env
            ).decode().split("=")[1].split()
        dmin = int(dmin)
        dmax = int(dmax)
    except Exception:
        host.WriteWarning("Unable to call sysctrl!\n Tests may fail because of bad port selection!")
        return

    rmin = dmin - 2000
    rmax = 65536 - dmax

    if rmax > amount:
        # Fill in ports, starting above the upper OS-usable port range.
        port = dmax + 1
        while port < 65536 and g_ports.qsize() < amount:
            if not PortOpen(port):
                host.WriteDebug(
                    '_setup_port_queue',
                    f"Adding a possible port to connect to: {port}")
                g_ports.put(port)
            else:
                host.WriteDebug(
                    '_setup_port_queue',
                    f"Rejecting a possible port to connect to: {port}")
            port += 1
    if g_ports.qsize() < amount < rmin:
        port = 2001
        # Fill in more ports, starting at 2001, well above well known ports,
        # and going up until the minimum port range used by the OS.
        while port < dmin and g_ports.qsize() < amount:
            if not PortOpen(port):
                host.WriteDebug(
                    '_setup_port_queue',
                    f"Adding a possible port to connect to: {port}")
                g_ports.put(port)
            else:
                host.WriteDebug(
                    '_setup_port_queue',
                    f"Rejecting a possible port to connect to: {port}")
            port += 1


def _get_port_by_bind():
    """
    Create a socket, bind with REUSEADDR, and return the bound port.

    Because SO_REUSEADDR is applied as an option to the socket, the future
    server should be able to use this port. This method is considered
    sub-optimal in comparison to the OS-unused port range method used above
    because another process might bind to this port in the meantime.

    Returns:
        A port value that can be used for a connection.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 0))  # bind to all interfaces on an ephemeral port
    port = sock.getsockname()[1]
    return port


def get_port(obj, name):
    '''
    Get a port and set it to the specified variable on the object.

    Args:
        obj: The object upon which to set the port variable.
        name: The name of the variable that receives the port value.

    Returns:
        The port value.
    '''
    _setup_port_queue()
    port = 0
    if g_ports.qsize() > 0:
        try:
            port = _get_available_port(g_ports)
            host.WriteVerbose(
                "get_port",
                f"Using port from port queue: {port}")
            # setup clean up step to recycle the port
            obj.Setup.Lambda(func_cleanup=lambda: g_ports.put(
                port), description="recycling port")
        except PortQueueSelectionError:
            port = _get_port_by_bind()
            host.WriteVerbose(
                "get_port",
                f"Queue was drained. Using port from a bound socket: {port}")
    else:
        # Since the queue could not be populated, use a port via bind.
        port = _get_port_by_bind()
        host.WriteVerbose(
            "get_port",
            f"Queue is empty. Using port from a bound socket: {port}")

    # Assign to the named variable.
    obj.Variables[name] = port
    return port
