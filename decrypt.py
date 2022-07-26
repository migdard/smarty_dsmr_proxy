import serial
import binascii
import argparse
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.exceptions import InvalidTag
from enum import Enum
from os import environ, unlink
from tempfile import NamedTemporaryFile
from subprocess import run, CalledProcessError

has_dsmr_parser = True
try:
    from dsmr_parser import telegram_specifications
    from dsmr_parser.exceptions import ParseError, InvalidChecksumError
    from dsmr_parser.parsers import TelegramParser

    from dsmr_parser import obis_references
    import dsmr_parser.obis_name_mapping
except ImportError:
    has_dsmr_parser = False

class State(Enum):
    STATE_IGNORING = 0
    # Start byte (hex "DB") has been detected.
    STATE_STARTED = 1
    # Length of system title has been read.
    STATE_HAS_SYSTEM_TITLE_LENGTH = 2
    # System title has been read.
    STATE_HAS_SYSTEM_TITLE = 3
    # Additional byte after the system title has been read.
    STATE_HAS_SYSTEM_TITLE_SUFFIX = 4
    # Length of remaining data has been read.
    STATE_HAS_DATA_LENGTH = 5
    # Additional byte after the remaining data length has been read.
    STATE_HAS_SEPARATOR = 6
    # Frame counter has been read.
    STATE_HAS_FRAME_COUNTER = 7
    # Payload has been read.
    STATE_HAS_PAYLOAD = 8
    # GCM tag has been read.
    STATE_HAS_GCM_TAG = 9
    # All input has been read. After this, we switch back to STATE_IGNORING and wait for a new start byte.
    STATE_DONE = 10

class SmartyProxy():
    def __init__(self):
        # Constants that describe the individual steps of the state machine:

        # Command line arguments
        self._args = {}

        # Serial connection from which we read the data from the smart meter
        self._connection = None

        # Initial empty values. These will be filled as content is read
        # and they will be reset each time we go back to the initial state.
        self._state = State.STATE_IGNORING
        self._buffer = ""
        self._buffer_length = 0
        self._next_state = 0
        self._system_title_length = 0
        self._system_title = b""
        self._data_length_bytes = b""  # length of "remaining data" in bytes
        self._data_length = 0  # length of "remaining data" as an integer
        self._frame_counter = b""
        self._payload = b""
        self._full_frame = b""
        self._gcm_tag = b""

    def main(self):
        # import serial.tools.list_ports as port_list
        # ports = list(port_list.comports())
        # for p in ports:
        #    print(p)
        parser = argparse.ArgumentParser()
        parser.add_argument('key', help="Decryption key")
        parser.add_argument('-i', '--serial-input-port', required=False, default="/dev/ttyUSB0", help="Input port. Defaults to /dev/ttyUSB0.")
        parser.add_argument('-d', '--decrypter', required=False, help="Decryptor executable")
        parser.add_argument('-o', '--serial-output-port', required=False, help="Output port, e.g. /dev/pts/2.")
        parser.add_argument('-a', '--aad', required=False, default="3000112233445566778899AABBCCDDEEFF", help="Additional authenticated data")
        parser.add_argument('-p', '--parse', action='store_true', required=False, default=False, help="Parse and pretty print DSMR v5 telegram")
        self._args = parser.parse_args()

        self.connect()
        while True:
            self.process()

    # Connect to the serial port when we run the script
    def connect(self):
        try:
            self._connection = serial.Serial(
                port=self._args.serial_input_port,
                baudrate=115200,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1
            )
        except (serial.SerialException, OSError) as err:
            print("ERROR", err)

    # Start processing incoming data
    def process(self):
        try:
            raw_data = self._connection.read()
            # print("read %d bytes" % len(raw_data))
        except serial.SerialException as e:
            print("Serial exception occurred: %s" % e)
            return -1

        # Read and parse the stream from the serial port byte by byte.
        # This parsing works as a state machine (see the definitions in the __init__ method).
        # See also the official documentation on http://smarty.creos.net/wp-content/uploads/P1PortSpecification.pdf
        # For better human readability, we use the hexadecimal representation of the input.
        hex_input = binascii.hexlify(raw_data)
        # print("read %s current state is %s" % (hex_input, self._state))
        # Initial state. Input is ignored until start byte is detected.
        if self._state == State.STATE_IGNORING:
            if hex_input == b'db':
                self._state = State.STATE_STARTED
                self._buffer = b""
                self._buffer_length = 1
                self._system_title_length = 0
                self._system_title = b""
                self._data_length = 0
                self._data_length_bytes = b""
                self._frame_counter = b""
                self._payload = b""
                self._full_frame = b'db'
                self._gcm_tag = b""
            else:
                return 0

        # Start byte (hex "DB") has been detected.
        elif self._state == State.STATE_STARTED:
            self._full_frame += hex_input
            self._state = State.STATE_HAS_SYSTEM_TITLE_LENGTH
            try:
                self._system_title_length = int(hex_input, 16)
            except ValueError as ex:
                print("Cannot read system title length, dropping frame" + str(ex))
                self._state = State.STATE_IGNORING
                return 0
            self._buffer_length = self._buffer_length + 1
            self._next_state = 2 + self._system_title_length  # start bytes + system title length

        # Length of system title has been read.
        elif self._state == State.STATE_HAS_SYSTEM_TITLE_LENGTH:
            self._full_frame += hex_input
            if self._buffer_length > self._next_state:
                self._system_title += hex_input
                self._state = State.STATE_HAS_SYSTEM_TITLE
                self._next_state = self._next_state + 2  # read two more bytes
            else:
                self._system_title += hex_input

        # System title has been read.
        elif self._state == State.STATE_HAS_SYSTEM_TITLE:
            self._full_frame += hex_input
            if hex_input == b'82':
                self._next_state = self._next_state + 1
                self._state = State.STATE_HAS_SYSTEM_TITLE_SUFFIX  # Ignore separator byte
            else:
                print("ERROR, expected 0x82 separator byte not found, dropping frame")
                self._state = State.STATE_IGNORING
 

        # Additional byte after the system title has been read.
        elif self._state == State.STATE_HAS_SYSTEM_TITLE_SUFFIX:
            self._full_frame += hex_input
            if self._buffer_length > self._next_state:
                self._data_length_bytes += hex_input
                self._data_length = int(self._data_length_bytes, 16)
                self._state = State.STATE_HAS_DATA_LENGTH
            else:
                self._data_length_bytes += hex_input

        # Length of remaining data has been read.
        elif self._state == State.STATE_HAS_DATA_LENGTH:
            self._full_frame += hex_input
            self._state = State.STATE_HAS_SEPARATOR  # Ignore separator byte
            self._next_state = self._next_state + 1 + 4  # separator byte + 4 bytes for framecounter

        # Additional byte after the remaining data length has been read.
        elif self._state == State.STATE_HAS_SEPARATOR:
            self._full_frame += hex_input
            if self._buffer_length > self._next_state:
                self._frame_counter += hex_input
                # print("Framecountermda2")
                # print(self._frame_counter)
                self._state = State.STATE_HAS_FRAME_COUNTER
                self._next_state = self._next_state + self._data_length - 17
            else:
                self._frame_counter += hex_input

        # Frame counter has been read.
        elif self._state == State.STATE_HAS_FRAME_COUNTER:
            self._full_frame += hex_input
            if len(raw_data) == 0:
                # we timed out, probable end of what we will get
                self._state = State.STATE_DONE
                self.analyze()
                self._state = State.STATE_IGNORING
            # FIXME for here we may not want to run the rest (always partial telegrams)
            if self._buffer_length > self._next_state:
                self._payload += hex_input
                self._state = State.STATE_HAS_PAYLOAD
                self._next_state = self._next_state + 12
            else:
                self._payload += hex_input

        # Payload has been read.
        elif self._state == State.STATE_HAS_PAYLOAD:
            self._full_frame += hex_input
            # All input has been read. After this, we switch back to STATE_IGNORING and wait for a new start byte.
            if self._buffer_length > self._next_state:
                self._gcm_tag += hex_input
                self._state = State.STATE_DONE
            else:
                self._gcm_tag += hex_input

        self._buffer += hex_input
        self._buffer_length = self._buffer_length + 1

        if self._state == State.STATE_DONE:
            # print(self._buffer)
            self.analyze()
            self._state = State.STATE_IGNORING

    # Once we have a full encrypted "telegram", put everything together for decryption.
    def analyze(self):
        key = binascii.unhexlify(self._args.key)
        additional_data = binascii.unhexlify(self._args.aad)
        iv = binascii.unhexlify(self._system_title + self._frame_counter)
        payload = binascii.unhexlify(self._payload)
        gcm_tag = binascii.unhexlify(self._gcm_tag)

        try:
            decryption = self.decrypt(
                key,
                additional_data,
                iv,
                payload,
                gcm_tag
            )
            try:
                decryption = decryption.decode('ascii')
            except UnicodeDecodeError as decode_ex:
                print("could not decode telegram")
                return
            # Cut partial last line if needed
            decryption = decryption[:decryption.rfind(")") + 1]
            if has_dsmr_parser and self._args.parse:
                # Add end of message
                decryption += "\r\n!"
                try:
                    # Extract the part for which the checksum applies.

                    checksum_contents = re.search(r'\/.+\!', decryption, re.DOTALL)
                    calculated_crc = TelegramParser.crc16(checksum_contents.group(0))
                    decryption += "%s\r\n" % hex(calculated_crc)[2:].upper()
                    print("calculated CRC is %d or %s\n" % (calculated_crc, hex(calculated_crc)[2:].upper()))
                    # expected_crc = int(checksum_hex.group(0), base=16)

                    verifying_parser = TelegramParser(telegram_specifications.V5)
                    #decryption += "AB12\r\n"
                    telegram = verifying_parser.parse(decryption)
                    print("passed !")
                except InvalidChecksumError as csum_ex:
                    print("Invalid checksum: %s" % csum_ex)
                except:
                    import sys
                    print(sys.exc_info()[1])
                try:
                    parser = TelegramParser(telegram_specifications.V5, apply_checksum_validation=False)
                    telegram = parser.parse(decryption)
                    for key in telegram:
                        print("%s: %s" % (dsmr_parser.obis_name_mapping.EN[key], telegram[key]))
                except InvalidChecksumError as csum_ex:
                    print("ERROR: Cannot parse DSMR Telegram" + str(csum_ex))
                    print(decryption)
                except ParseError as parse_err:
                    print("ERROR: Cannot parse DSMR Telegram" + str(parse_err))
                    print(decryption)
                except:
                    import sys
                    print(sys.exc_info()[1])
            else:
                print(decryption)


            if self._args.serial_output_port:
                decryption = decryption.encode()
                print("writing to serial:\n%s" % decryption)
                self.write_to_serial_port(decryption)
        except InvalidTag:
            print("ERROR: Invalid Tag.")

    # Do the actual decryption (AES-GCM)
    def decrypt(self, key, additional_data, iv, payload, gcm_tag, external_decrypt=True):
        if external_decrypt:
            # print("WRITING file")
            # with open("cipher.bin", "wb") as dtc:
            with NamedTemporaryFile(mode='w+b', delete=False) as out_file:
                temp_file_name = out_file.name
                out_file.write(binascii.unhexlify(self._buffer))

        # print(" WROTE to %s bytes:%d" % (temp_file_name, self._buffer_length))
        try:
            proc = run([self._args.decrypter, temp_file_name],
                       check=True, capture_output=True)
        except CalledProcessError as ex:
            print("Error running decryptor " + str(ex))
            return
        unlink(temp_file_name)
        return proc.stdout
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, gcm_tag, 12),
            backend=default_backend()
        ).decryptor()

        decryptor.authenticate_additional_data(additional_data)

        return decryptor.update(payload) + decryptor.finalize()

    # Write the decrypted data to a serial port (e.g. one created with socat)
    def write_to_serial_port(self, decryption):
        ser = serial.Serial(
            port=self._args.serial_output_port,
            baudrate=115200,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
        )
        ser.write(decryption)
        ser.close()


if __name__ == '__main__':
    smarty_proxy = SmartyProxy()
    smarty_proxy.main()
