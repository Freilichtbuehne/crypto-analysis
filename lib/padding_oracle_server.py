'''
    A simple tcp that will server as a PKCS#7 padding oracle.
    It is designed to serve one client at a time.
'''

import socket, logging
from lib.aes_cbc import AES_CBC

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(levelname)s: [SERVER] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)


class PaddingOracleSession:
    STATE_CIPHERTEXT = 0
    STATE_BLOCKCOUNT = 1
    STATE_BLOCKS = 2

    def __init__(self, conn, aes_cbc, plaintext_override=None):
        self.conn = conn
        self.closed = False
        self.aes = aes_cbc
        self.plaintext_override = plaintext_override
        self.states = {
            self.STATE_CIPHERTEXT: {
                'func': self.handle_ciphertext,
                'read_size': 16,
                'ciphertext': None,
                'plaintext': None,
            },
            self.STATE_BLOCKCOUNT: {
                'func': self.handle_blockcount,
                'read_size': 2,
                'block_count': None,
            },
            self.STATE_BLOCKS: {
                'func': self.handle_blocks,
                'read_size': 16,
                'response': list(),
            },
        }
        self.cur_state = self.STATE_CIPHERTEXT

    def fail(self, message=None):
        self.closed = True
        self.conn.close()
        if message is not None: logger.info(f'Closing connection: {message}')

    def handle_ciphertext(self, state, data):
        logger.info(f'Received ciphertext: {data.hex()}')
        self.states[state]['ciphertext'] = data

        # Generate plaintext or use override value
        plaintext = None
        if self.plaintext_override is None:
            plaintext = self.aes.decrypt(data)
        else:
            plaintext = self.plaintext_override

        self.states[state]['plaintext'] = plaintext
        logger.info(f'Plaintext: {plaintext.hex()}')

        # Set next state
        self.cur_state = self.STATE_BLOCKCOUNT

    def handle_blockcount(self, state, data):
        logger.debug(f'Received block count: {data.hex()}')
        # convert the data to an integer
        block_count = int.from_bytes(data, byteorder='little')
        # Fail connection if block count is invalid
        if block_count < 1 or block_count > 256:
            self.fail(f'Invalid block count {block_count}')
            return

        logger.debug(f'Block count: {block_count}')
        self.states[state]['block_count'] = block_count
        # Set next state
        self.cur_state = self.STATE_BLOCKS

    def handle_blocks(self, state, data):
        logger.debug(f"Received block ({len(self.states[state]['response'])}): {data.hex()}")

        # Check if the padding is correct
        xored = self.aes.xor(data, self.states[self.STATE_CIPHERTEXT]['plaintext'])
        correct = self.aes.unpad(xored) is not None
        self.states[state]['response'].append(correct)

        # Skip if we haven't received all blocks yet
        if len(self.states[state]['response']) < self.states[self.STATE_BLOCKCOUNT]['block_count']: return

        logger.debug(f'Received all blocks')
        # Send a history of all blocks if the padding was correct or not
        response = bytes(self.states[state]['response'])
        logger.debug(f'Sending response: {response.hex()}')
        self.conn.sendall(response)

        # Clear the response
        self.states[state]['response'].clear()

        # Set next state
        self.cur_state = self.STATE_BLOCKCOUNT

    def read(self):
        read_size = self.states[self.cur_state]['read_size']
        data = self.conn.recv(read_size)

        if len(data) == 0:
            self.fail('Received empty data')
            return

        # Check if client sent expected amount of data
        if len(data) < read_size:
            self.fail(f'Received {len(data)} bytes, expected {read_size} bytes')
            return

        # Call the appropriate handler
        self.states[self.cur_state]['func'](self.cur_state, data)

    def is_open(self):
        return self.conn is not None and not self.closed

class PaddingOracleServer(object):
    def __init__(self, hostname='localhost', port=18732, key=bytes.fromhex(16*"00"), iv=bytes.fromhex(16*"00"), plaintext_override=None):
        self.address = (hostname, port)
        self.socket = None
        self.backlog = 1
        self.timeout = 10
        self.plaintext = plaintext_override
        self.key = key
        self.iv = iv

    def close(self, message=None):
        if self.socket is None: return
        if message is not None: logger.info(f'Closing socket: {message}')
        self.socket.close()

    def handle_client(self, conn):
        # Create a new session
        aes_cbc = AES_CBC(self.key, self.iv)
        session = PaddingOracleSession(conn, aes_cbc, self.plaintext)
        while session.is_open():
           session.read()

    def run(self):
        # Create a new socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(self.address)
        self.socket.listen(self.backlog)
        self.socket.settimeout(self.timeout)
        logger.info('Listening on {}:{}'.format(*self.address))

        active = True
        while active:
            # Check if the socket is still open
            if self.socket is None: break

            conn, addr = None, None
            try:
                # Accept a new connection
                conn, addr = self.socket.accept()
                logger.info('Accepted connection from {}:{}'.format(*addr))
                self.handle_client(conn)
            except socket.timeout:
                # Ignore timeout errors
                continue
            except KeyboardInterrupt:
                # Close the socket on keyboard interrupt
                self.close('Keyboard interrupt')
                active = False
                break
            finally:
                # Close the connection
                if conn is None: continue
                logger.info('Closing connection')
                conn.close()
                active = False
