import hashlib
import binascii
import struct
import time
import optparse
from construct import *


def main():
    options = get_args()

    # В Bitcoin Genesis Block алгоритм SHA256
    algorithm = 'SHA256'  # Определяем алгоритм как константу

    # Создание input и output скриптов
    input_script = create_input_script(options.timestamp)
    output_script = create_output_script(options.pubkey)

    # Генерация транзакции
    tx = create_transaction(input_script, output_script, options)

    # Вычисление Merkle Root (двойное SHA256)
    hash_merkle_root = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
    print(f"Calculated Merkle Root: {binascii.hexlify(hash_merkle_root).decode()}")

    # Вывод информации о блоке
    print_block_info(options, hash_merkle_root, algorithm)  # Передаем алгоритм как аргумент

    # Генерация заголовка блока
    block_header = create_block_header(hash_merkle_root, options.time, options.bits, options.nonce)

    # Генерация хэша блока (необходимо для поиска нужного nonce)
    genesis_hash, nonce = generate_hash(block_header, algorithm, options.nonce, options.bits)
    announce_found_genesis(genesis_hash, nonce)


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--time", dest="time", default=int(time.time()), type="int", help="the (unix) time when the genesisblock is created")
    parser.add_option("-z", "--timestamp", dest="timestamp", default="The Times 03/Jan/2009 Chancellor on brink of second bailout for banks", type="string", help="the pszTimestamp found in the coinbase of the genesisblock")
    parser.add_option("-n", "--nonce", dest="nonce", default=0, type="int", help="the first value of the nonce that will be incremented when searching the genesis hash")
    parser.add_option("-p", "--pubkey", dest="pubkey", default="04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f", type="string", help="the pubkey found in the output script")
    parser.add_option("-v", "--value", dest="value", default=5000000000, type="int", help="the value in coins for the output, full value (exp. in bitcoin 5000000000 - To get other coins value: Block Value * 100000000)")
    parser.add_option("-b", "--bits", dest="bits", type="int", help="the target in compact representation, associated to a difficulty of 1")

    (options, args) = parser.parse_args()
    if not options.bits:
        options.bits = 0x1d00ffff  # Задать стандартное значение для Bitcoin

    return options


def create_input_script(psz_timestamp):
    psz_prefix = "04ffff001d0104"
    script_prefix = psz_prefix + chr(len(psz_timestamp))  # Длина строки
    return (script_prefix + binascii.hexlify(psz_timestamp.encode('utf-8')).decode()).encode('utf-8')


def create_output_script(pubkey):
    script_len = '41'
    OP_CHECKSIG = 'ac'
    return (script_len + pubkey + OP_CHECKSIG).encode('utf-8')


def create_transaction(input_script, output_script, options):
    input_script_len = len(input_script)
    output_script_len = len(output_script)

    # Структура транзакции
    transaction = Struct("transaction",
                         Bytes("version", 4),
                         Byte("num_inputs"),
                         StaticField("prev_output", 32),
                         UBInt32('prev_out_idx'),
                         Byte('input_script_len'),
                         Bytes('input_script', input_script_len),
                         UBInt32('sequence'),
                         Byte('num_outputs'),
                         Bytes('out_value', 8),
                         Byte('output_script_len'),
                         Bytes('output_script', output_script_len),
                         UBInt32('locktime'))

    # Заполнение данных для транзакции
    tx = transaction.parse(b'\x00' * (127 + input_script_len + output_script_len))
    tx.version = struct.pack('<I', 1)
    tx.num_inputs = 1
    tx.prev_output = struct.pack('<qqqq', 0, 0, 0, 0)
    tx.prev_out_idx = 0xFFFFFFFF
    tx.input_script_len = input_script_len
    tx.input_script = input_script
    tx.sequence = 0xFFFFFFFF
    tx.num_outputs = 1
    tx.out_value = struct.pack('<q', options.value)
    tx.output_script_len = output_script_len
    tx.output_script = output_script
    tx.locktime = 0
    return transaction.build(tx)


def create_block_header(hash_merkle_root, time, bits, nonce):
    block_header = Struct("block_header",
                         Bytes("version", 4),
                         Bytes("hash_prev_block", 32),
                         Bytes("hash_merkle_root", 32),
                         Bytes("time", 4),
                         Bytes("bits", 4),
                         Bytes("nonce", 4))

    genesisblock = block_header.parse(b'\x00' * 80)
    genesisblock.version = struct.pack('<I', 1)
    genesisblock.hash_prev_block = struct.pack('<qqqq', 0, 0, 0, 0)  # Для первого блока предыдущий блок равен 0
    genesisblock.hash_merkle_root = hash_merkle_root
    genesisblock.time = struct.pack('<I', time)
    genesisblock.bits = struct.pack('<I', bits)
    genesisblock.nonce = struct.pack('<I', nonce)
    return block_header.build(genesisblock)


def generate_hash(data_block, algorithm, start_nonce, bits):
    print('Searching for genesis hash..')
    nonce = start_nonce
    last_updated = time.time()
    target = (bits & 0xffffff) * 2**(8 * ((bits >> 24) - 3))

    while True:
        sha256_hash, header_hash = generate_hashes_from_block(data_block, algorithm)
        last_updated = calculate_hashrate(nonce, last_updated)
        if is_genesis_hash(header_hash, target):
            return (header_hash, nonce)
        else:
            nonce = nonce + 1
            data_block = data_block[0:len(data_block) - 4] + struct.pack('<I', nonce)


def generate_hashes_from_block(data_block, algorithm):
    sha256_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
    header_hash = sha256_hash
    return sha256_hash, header_hash


def is_genesis_hash(header_hash, target):
    return int(binascii.hexlify(header_hash), 16) < target


def calculate_hashrate(nonce, last_updated):
    current_time = time.time()
    elapsed = current_time - last_updated
    if elapsed >= 1.0:
        hashrate = nonce / elapsed
        #print("\rHashrate: %.2f H/s" % hashrate)
        return current_time
    return last_updated


def print_block_info(options, hash_merkle_root, algorithm):
    print(f"block hash algorithm: {algorithm}")  # Используем переданный алгоритм
    print(f"block time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(options.time))}")
    print(f"pszTimestamp: {options.timestamp}")
    print(f"hashMerkleRoot: {binascii.hexlify(hash_merkle_root).decode()}")


def announce_found_genesis(genesis_hash, nonce):
    print(f"Genesis block found: {binascii.hexlify(genesis_hash).decode()}")
    print(f"nonce: {nonce}")


if __name__ == '__main__':
    main()

