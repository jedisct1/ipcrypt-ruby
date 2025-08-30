# frozen_string_literal: true

require 'ipaddr'
require 'openssl'

module IPCrypt
  # Implementation of ipcrypt-ndx using AES-XTS with a 16-byte tweak
  class NDX
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

    # Encrypt using AES-XTS construction
    def self.aes_xts_encrypt(key, tweak, plaintext)
      raise InvalidKeyError, 'Key must be 32 bytes' unless key.length == 32
      raise InvalidTweakError, 'Tweak must be 16 bytes' unless tweak.length == 16
      raise InvalidDataError, 'Plaintext must be 16 bytes' unless plaintext.length == 16

      # Split key into two 16-byte keys
      k1 = key[0, 16]
      k2 = key[16, 16]

      # Encrypt tweak with second key
      cipher2 = OpenSSL::Cipher.new('AES-128-ECB')
      cipher2.encrypt
      cipher2.padding = 0 # Disable padding
      cipher2.key = k2
      et = cipher2.update(tweak) + cipher2.final

      # XOR plaintext with encrypted tweak
      xored = plaintext.bytes.zip(et.bytes).map { |a, b| a ^ b }.pack('C*')

      # Encrypt with first key
      cipher1 = OpenSSL::Cipher.new('AES-128-ECB')
      cipher1.encrypt
      cipher1.padding = 0 # Disable padding
      cipher1.key = k1
      encrypted = cipher1.update(xored) + cipher1.final

      # XOR result with encrypted tweak
      encrypted.bytes.zip(et.bytes).map { |a, b| a ^ b }.pack('C*')
    end

    # Decrypt using AES-XTS construction
    def self.aes_xts_decrypt(key, tweak, ciphertext)
      raise InvalidKeyError, 'Key must be 32 bytes' unless key.length == 32
      raise InvalidTweakError, 'Tweak must be 16 bytes' unless tweak.length == 16
      raise InvalidDataError, 'Ciphertext must be 16 bytes' unless ciphertext.length == 16

      # Split key into two 16-byte keys
      k1 = key[0, 16]
      k2 = key[16, 16]

      # Encrypt tweak with second key
      cipher2 = OpenSSL::Cipher.new('AES-128-ECB')
      cipher2.encrypt
      cipher2.padding = 0 # Disable padding
      cipher2.key = k2
      et = cipher2.update(tweak) + cipher2.final

      # XOR ciphertext with encrypted tweak
      xored = ciphertext.bytes.zip(et.bytes).map { |a, b| a ^ b }.pack('C*')

      # Decrypt with first key
      cipher1 = OpenSSL::Cipher.new('AES-128-ECB')
      cipher1.decrypt
      cipher1.padding = 0 # Disable padding
      cipher1.key = k1
      decrypted = cipher1.update(xored) + cipher1.final

      # XOR result with encrypted tweak
      decrypted.bytes.zip(et.bytes).map { |a, b| a ^ b }.pack('C*')
    end

    # Encrypt an IP address using AES-XTS
    def self.encrypt(ip, key)
      raise InvalidKeyError, 'Key must be 32 bytes' unless key.length == 32

      # Generate random 16-byte tweak
      tweak = OpenSSL::Random.random_bytes(16)

      # Convert IP to bytes and encrypt
      plaintext = ip_to_bytes(ip)
      ciphertext = aes_xts_encrypt(key, tweak, plaintext)

      # Return tweak || ciphertext
      tweak + ciphertext
    end

    # Decrypt a binary output using AES-XTS
    def self.decrypt(binary_output, key)
      raise InvalidKeyError, 'Key must be 32 bytes' unless key.length == 32
      raise InvalidDataError, 'Binary output must be 32 bytes' unless binary_output.length == 32

      # Split into tweak and ciphertext
      tweak = binary_output[0, 16]
      ciphertext = binary_output[16, 16]

      # Decrypt and convert back to IP
      plaintext = aes_xts_decrypt(key, tweak, ciphertext)
      bytes_to_ip(plaintext)
    end
  end
end
