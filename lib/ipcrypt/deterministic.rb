# frozen_string_literal: true

require 'ipaddr'
require 'openssl'

module IPCrypt
  # Implementation of ipcrypt-deterministic using AES-128
  class Deterministic
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

    # Encrypt an IP address using AES-128
    def self.encrypt(ip, key)
      raise InvalidKeyError, 'Key must be 16 bytes' unless key.length == 16

      plaintext = ip_to_bytes(ip)
      cipher = OpenSSL::Cipher.new('AES-128-ECB')
      cipher.encrypt
      cipher.padding = 0 # Disable padding for exact 16-byte blocks
      cipher.key = key
      ciphertext = cipher.update(plaintext) + cipher.final

      bytes_to_ip(ciphertext)
    end

    # Decrypt an IP address using AES-128
    def self.decrypt(ip, key)
      raise InvalidKeyError, 'Key must be 16 bytes' unless key.length == 16

      ciphertext = ip_to_bytes(ip)
      cipher = OpenSSL::Cipher.new('AES-128-ECB')
      cipher.decrypt
      cipher.padding = 0 # Disable padding for exact 16-byte blocks
      cipher.key = key
      plaintext = cipher.update(ciphertext) + cipher.final

      bytes_to_ip(plaintext)
    end
  end
end
