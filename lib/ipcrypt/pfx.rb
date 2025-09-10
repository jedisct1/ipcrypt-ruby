# frozen_string_literal: true

require 'ipaddr'
require 'openssl'

module IPCrypt
  # Implementation of ipcrypt-pfx using AES-128 for prefix-preserving encryption
  class Pfx
    # Convert an IP address to its 16-byte representation
    def self.ip_to_bytes(ip)
      ip_addr = ip.is_a?(String) ? IPAddr.new(ip) : ip
      if ip_addr.ipv4?
        # Convert IPv4 to IPv4-mapped IPv6 format (::ffff:0:0/96)
        bytes = [0] * 10 + [0xff, 0xff] + ip_addr.hton.bytes
        bytes.pack('C*').force_encoding('BINARY')
      else
        ip_addr.hton.force_encoding('BINARY')
      end
    end

    # Convert a 16-byte representation back to an IP address
    def self.bytes_to_ip(bytes16)
      raise InvalidDataError, 'Input must be 16 bytes' unless bytes16.length == 16

      # Check for IPv4-mapped IPv6 format
      zero_bytes = [0] * 10
      ff_bytes = [255, 255]

      if bytes16[0, 10].bytes == zero_bytes && bytes16[10, 2].bytes == ff_bytes
        IPAddr.new_ntoh(bytes16[12, 4])
      else
        IPAddr.new_ntoh(bytes16)
      end
    end

    # Check if a 16-byte array has the IPv4-mapped IPv6 prefix (::ffff:0:0/96)
    def self.ipv4_mapped?(bytes16)
      return false unless bytes16.length == 16

      # Check for IPv4-mapped prefix: first 10 bytes are 0x00, bytes 10-11 are 0xFF
      bytes16[0, 10].bytes == [0] * 10 && bytes16[10, 2].bytes == [255, 255]
    end

    # Extract bit at position from 16-byte array
    # position: 0 = LSB of byte 15, 127 = MSB of byte 0
    def self.get_bit(data, position)
      byte_index = 15 - (position / 8)
      bit_index = position % 8
      (data.bytes[byte_index] >> bit_index) & 1
    end

    # Set bit at position in 16-byte array
    # position: 0 = LSB of byte 15, 127 = MSB of byte 0
    def self.set_bit(data, position, value)
      byte_index = 15 - (position / 8)
      bit_index = position % 8
      bytes = data.bytes
      bytes[byte_index] |= value << bit_index
      bytes.pack('C*')
    end

    # Shift a 16-byte array one bit to the left
    # The most significant bit is lost, and a zero bit is shifted in from the right
    def self.shift_left_one_bit(data)
      raise InvalidDataError, 'Input must be 16 bytes' unless data.length == 16

      bytes = data.bytes
      result = Array.new(16, 0)
      carry = 0

      # Process from least significant byte (byte 15) to most significant (byte 0)
      15.downto(0) do |i|
        # Current byte shifted left by 1, with carry from previous byte
        result[i] = ((bytes[i] << 1) | carry) & 0xFF
        # Extract the bit that will be carried to the next byte
        carry = (bytes[i] >> 7) & 1
      end

      result.pack('C*')
    end

    # Pad prefix for prefix_len_bits=0 (IPv6)
    # Sets separator bit at position 0 (LSB of byte 15)
    def self.pad_prefix_zero
      padded = Array.new(16, 0)
      padded[15] = 0x01 # Set bit at position 0 (LSB of byte 15)
      padded.pack('C*')
    end

    # Pad prefix for prefix_len_bits=96 (IPv4)
    # For IPv4, the data always has format: 00...00 ffff xxxx (IPv4-mapped)
    # Result: 00000001 00...00 0000ffff (separator at pos 96, then 96 bits)
    def self.pad_prefix_ninetysix(_data)
      # The result is always the same for IPv4 addresses since they all have
      # the same IPv4-mapped prefix (00...00 ffff)
      padded = Array.new(16, 0)
      padded[3] = 0x01 # Set bit at position 96 (bit 0 of byte 3)
      padded[14] = 0xFF
      padded[15] = 0xFF
      padded.pack('C*')
    end

    # Encrypt an IP address using ipcrypt-pfx
    def self.encrypt(ip, key)
      raise InvalidKeyError, 'Key must be 32 bytes' unless key.length == 32

      # Split the key into two AES-128 keys
      k1 = key[0, 16]
      k2 = key[16, 16]

      # Check that K1 and K2 are different
      raise InvalidKeyError, 'The two halves of the key must be different' if k1 == k2

      # Convert IP to 16-byte representation
      bytes16 = ip_to_bytes(ip)

      # Initialize encrypted result with zeros
      encrypted = Array.new(16, 0)

      # Determine starting point
      if ipv4_mapped?(bytes16)
        prefix_start = 96
        # If IPv4-mapped, copy the IPv4-mapped prefix
        encrypted[0, 12] = bytes16[0, 12].bytes
      else
        prefix_start = 0
      end

      # Create AES cipher objects
      cipher1 = OpenSSL::Cipher.new('AES-128-ECB')
      cipher1.encrypt
      cipher1.padding = 0
      cipher1.key = k1

      cipher2 = OpenSSL::Cipher.new('AES-128-ECB')
      cipher2.encrypt
      cipher2.padding = 0
      cipher2.key = k2

      # Initialize padded_prefix for the starting prefix length
      padded_prefix = if ipv4_mapped?(bytes16)
                        pad_prefix_ninetysix(bytes16)
                      else # prefix_start == 0
                        pad_prefix_zero
                      end

      # Process each bit position
      (prefix_start...128).each do |prefix_len_bits|
        # Compute pseudorandom function with dual AES encryption
        e1 = cipher1.update(padded_prefix) + cipher1.final
        e2 = cipher2.update(padded_prefix) + cipher2.final

        # XOR the two encryptions
        e = e1.bytes.zip(e2.bytes).map { |a, b| a ^ b }.pack('C*')
        # We only need the least significant bit of byte 15
        cipher_bit = e.bytes[15] & 1

        # Extract the current bit from the original IP
        current_bit_pos = 127 - prefix_len_bits

        # Set the bit in the encrypted result
        original_bit = get_bit(bytes16, current_bit_pos)
        encrypted_bytes = encrypted.pack('C*')
        encrypted_bytes = set_bit(encrypted_bytes, current_bit_pos, cipher_bit ^ original_bit)
        encrypted = encrypted_bytes.bytes

        # Prepare padded_prefix for next iteration
        # Shift left by 1 bit and insert the next bit from bytes16
        padded_prefix = shift_left_one_bit(padded_prefix)
        padded_prefix = set_bit(padded_prefix, 0, original_bit)
      end

      bytes_to_ip(encrypted.pack('C*'))
    end

    # Decrypt an IP address using ipcrypt-pfx
    def self.decrypt(encrypted_ip, key)
      raise InvalidKeyError, 'Key must be 32 bytes' unless key.length == 32

      # Split the key into two AES-128 keys
      k1 = key[0, 16]
      k2 = key[16, 16]

      # Check that K1 and K2 are different
      raise InvalidKeyError, 'The two halves of the key must be different' if k1 == k2

      # Convert encrypted IP to 16-byte representation
      encrypted_bytes = ip_to_bytes(encrypted_ip)

      # Initialize decrypted result
      decrypted = Array.new(16, 0)

      # For decryption, we need to determine if this was originally IPv4-mapped
      # IPv4-mapped addresses are encrypted with prefix_start=96
      if ipv4_mapped?(encrypted_bytes)
        prefix_start = 96
        # If this was originally IPv4, set up the IPv4-mapped IPv6 prefix
        decrypted[10] = 0xff
        decrypted[11] = 0xff
      else
        prefix_start = 0
      end

      # Create AES cipher objects
      cipher1 = OpenSSL::Cipher.new('AES-128-ECB')
      cipher1.encrypt
      cipher1.padding = 0
      cipher1.key = k1

      cipher2 = OpenSSL::Cipher.new('AES-128-ECB')
      cipher2.encrypt
      cipher2.padding = 0
      cipher2.key = k2

      # Initialize padded_prefix for the starting prefix length
      padded_prefix = if prefix_start.zero?
                        pad_prefix_zero
                      else # prefix_start == 96
                        pad_prefix_ninetysix(decrypted.pack('C*'))
                      end

      # Process each bit position
      (prefix_start...128).each do |prefix_len_bits|
        # Compute pseudorandom function with dual AES encryption
        e1 = cipher1.update(padded_prefix) + cipher1.final
        e2 = cipher2.update(padded_prefix) + cipher2.final

        # XOR the two encryptions
        e = e1.bytes.zip(e2.bytes).map { |a, b| a ^ b }.pack('C*')
        # We only need the least significant bit of byte 15
        cipher_bit = e.bytes[15] & 1

        # Extract the current bit from the encrypted IP
        current_bit_pos = 127 - prefix_len_bits

        # Set the bit in the decrypted result
        encrypted_bit = get_bit(encrypted_bytes, current_bit_pos)
        original_bit = cipher_bit ^ encrypted_bit
        decrypted_bytes = decrypted.pack('C*')
        decrypted_bytes = set_bit(decrypted_bytes, current_bit_pos, original_bit)
        decrypted = decrypted_bytes.bytes

        # Prepare padded_prefix for next iteration
        # Shift left by 1 bit and insert the next bit from decrypted
        padded_prefix = shift_left_one_bit(padded_prefix)
        padded_prefix = set_bit(padded_prefix, 0, original_bit)
      end

      bytes_to_ip(decrypted.pack('C*'))
    end
  end
end
