import asyncio
import logging
from collections import namedtuple

ReceivedDatagram = namedtuple("ReceivedDatagram", ["data", "addr"])


class UdpEndpointClosedError(Exception):
    """Raised when trying to read/write on a closed UDP endpoint."""
    pass


class UdpEndpointProtocol(asyncio.DatagramProtocol):
    """
    Internal protocol class bridging asyncio callbacks to the reader/writer.
    """
    def __init__(self, incoming_queue: asyncio.Queue):
        self.queue = incoming_queue
        self.transport = None
        self._error = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        # Put received data and address into the queue for the reader
        try:
            self.queue.put_nowait(ReceivedDatagram(data=data, addr=addr))
        except asyncio.QueueFull:
            logging.warning(f"Incoming UDP queue is full. Packet from {addr} dropped.")

    def error_received(self, exc: Exception):
        # An error occurred, often related to sending (e.g., ICMP port unreachable)
        print(f"UDP Endpoint Error: {exc}")
        self._error = exc
        # Put the error in the queue to notify the reader
        asyncio.create_task(self.queue.put(exc))
        # Optionally close transport on error? Depends on desired behavior.
        # self.transport.close() # This would trigger connection_lost

    def connection_lost(self, exc: Exception | None):
        # The transport was closed
        self._error = self._error or exc  # Keep first error if multiple occur
        # Signal the end to the reader by putting None (or the exception) in the queue
        final_signal = self._error if self._error else None
        asyncio.create_task(self.queue.put(final_signal))


class UdpReader:
    def __init__(self, queue: asyncio.Queue, transport: asyncio.DatagramTransport):
        self._queue = queue
        self._transport = transport

    async def read(self) -> ReceivedDatagram | None:
        """
        Waits for and returns the next incoming datagram (data, addr).
        Raises UdpEndpointClosedError if the endpoint is closed or an error occurred.
        """
        if self._queue.empty() and not self._transport or self._transport.is_closing():
            raise UdpEndpointClosedError("Reader is closed.")

        # Wait for an item from the protocol
        item = await self._queue.get()

        if isinstance(item, ReceivedDatagram):
            return item
        elif item is None:  # Normal closure signal
            self._transport = None
            return None
        elif isinstance(item, Exception):  # Error signal
            self._transport = None
            raise UdpEndpointClosedError(f"Endpoint closed due to error: {item}") from item
        else:  # Should not happen with the current protocol implementation
            raise TypeError(f"Unexpected item in queue: {item!r}")

    def close(self):
        """Closes the underlying transport."""
        if self._transport:
            self._transport.close()
            self._transport = None


# --- Writer Class ---
class UdpWriter:
    def __init__(self, transport: asyncio.DatagramTransport, remote_addr: tuple | None):
        self._transport = transport
        self._remote_addr = remote_addr  # Default destination (if set)

    def write(self, data: bytes, addr: tuple | None = None):
        """
        Sends a datagram.
        If addr is None, sends to the default remote_addr (if configured).
        Raises ValueError if addr is None and no default remote_addr exists.
        Raises UdpEndpointClosedError if the endpoint is closed.
        """
        if not self._transport or self._transport.is_closing():
            raise UdpEndpointClosedError("endpoint is closing.")

        destination = addr or self._remote_addr
        if destination is None:
            raise ValueError("Destination address required (or set remote_addr during endpoint creation).")

        try:
            self._transport.sendto(data, destination)
        except OSError as e:
            # Can potentially happen if buffers are full, etc.
            print(f"Error sending UDP packet: {e}")
            # Re-raise or handle as appropriate
            raise
        except Exception as e:
            print(f"Unexpected error sending UDP packet: {e}")
            raise

    def close(self):
        """Closes the underlying transport."""
        if self._transport:
            self._transport.close()
            self._transport = None

    def get_extra_info(self, name: str, default=None):
        """Gets extra information from the transport."""
        return self._transport.get_extra_info(name, default)

    def set_default_remote_addr(self, addr):
        self._remote_addr = addr


# --- Factory Function ---
async def open_udp_endpoint(
        local_addr: tuple | None = None,
        remote_addr: tuple | None = None,
        *,  # Keyword-only arguments follow
        queue_size: int = 8192,  # 0 for unlimited
        family: int = 0
) -> tuple[UdpReader, UdpWriter]:
    """
    Creates a UDP endpoint and returns a (reader, writer) pair.

    Args:
        local_addr: Tuple (host, port) to bind locally. If None, OS chooses port.
        remote_addr: Tuple (host, port) default destination for writer.write().
        queue_size: Max size of the incoming datagram queue (0 for unlimited).
        family: Address family (socket.AF_INET, socket.AF_INET6, etc.). If None, OS chooses.

    Returns:
        A tuple (UdpReader, UdpWriter).
    """
    loop = asyncio.get_running_loop()
    incoming_queue = asyncio.Queue(maxsize=queue_size)

    # Create the datagram endpoint using our custom protocol
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UdpEndpointProtocol(incoming_queue),
        local_addr=local_addr,
        remote_addr=remote_addr,
        family=family
    )

    # Create and return the reader/writer objects
    reader = UdpReader(incoming_queue, transport)
    # Pass the configured remote_addr to the writer for its default behavior
    writer = UdpWriter(transport, remote_addr)

    return reader, writer