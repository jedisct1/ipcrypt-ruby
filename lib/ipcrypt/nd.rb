# frozen_string_literal: true

require 'ipaddr'
require 'openssl'

module IPCrypt
  # Implementation of ipcrypt-nd using KIASU-BC
  class ND
    # AES S-box and inverse S-box
    SBOX = [
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ].freeze

    INV_SBOX = [
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
      0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
      0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
      0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
      0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
      0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
      0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
      0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
      0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
      0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
      0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
      0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
      0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
      0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ].freeze

    # AES round constants
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36].freeze

    # Precomputed multiplication tables for AES operations
    MUL2 = (0..255).map do |x|
      ((x << 1) & 0xFF) ^ (x & 0x80 != 0 ? 0x1B : 0)
    end.freeze

    MUL3 = (0..255).map do |x|
      MUL2[x] ^ x
    end.freeze

    # Specialized GF multiplication by 0x09 (x^3 + 1)
    def self.gf_mul_09(a)
      # 0x09 = x^3 + 1 = MUL2[MUL2[MUL2[a]]] ^ a
      MUL2[MUL2[MUL2[a]]] ^ a
    end

    # Specialized GF multiplication by 0x0B (x^3 + x + 1)
    def self.gf_mul_0b(a)
      # 0x0B = x^3 + x + 1 = MUL2[MUL2[MUL2[a]]] ^ MUL2[a] ^ a
      MUL2[MUL2[MUL2[a]]] ^ MUL2[a] ^ a
    end

    # Specialized GF multiplication by 0x0D (x^3 + x^2 + 1)
    def self.gf_mul_0d(a)
      # 0x0D = x^3 + x^2 + 1 = MUL2[MUL2[MUL2[a]]] ^ MUL2[MUL2[a]] ^ a
      MUL2[MUL2[MUL2[a]]] ^ MUL2[MUL2[a]] ^ a
    end

    # Specialized GF multiplication by 0x0E (x^3 + x^2 + x)
    def self.gf_mul_0e(a)
      # 0x0E = x^3 + x^2 + x = MUL2[MUL2[MUL2[a]]] ^ MUL2[MUL2[a]] ^ MUL2[a]
      MUL2[MUL2[MUL2[a]]] ^ MUL2[MUL2[a]] ^ MUL2[a]
    end

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

    # Rotate a 4-byte word
    def self.rot_word(word)
      word[1..] + word[0]
    end

    # Generate AES round keys
    def self.expand_key(key)
      raise InvalidKeyError, 'Key must be 16 bytes' unless key.length == 16

      round_keys = [key]
      10.times do |i|
        prev_key = round_keys.last
        temp = prev_key[-4..]
        temp = rot_word(temp)
        temp = temp.bytes.map { |b| SBOX[b] }.pack('C*')
        temp[0] = (temp[0].ord ^ RCON[i]).chr

        new_key = ''
        4.times do |j|
          word = prev_key[j * 4, 4]
          word = if j.zero?
                   word.bytes.zip(temp.bytes).map { |a, b| a ^ b }.pack('C*')
                 else
                   word.bytes.zip(new_key[(j - 1) * 4, 4].bytes).map { |a, b| a ^ b }.pack('C*')
                 end
          new_key += word
        end
        round_keys << new_key
      end

      round_keys
    end

    # Pad an 8-byte tweak to 16 bytes by placing each 2-byte pair at the start of each 4-byte group
    def self.pad_tweak(tweak)
      raise InvalidTweakError, 'Tweak must be 8 bytes' unless tweak.length == 8

      padded_bytes = [0] * 16
      4.times do |i|
        padded_bytes[i * 4] = tweak[i * 2].ord
        padded_bytes[i * 4 + 1] = tweak[i * 2 + 1].ord
        # padded_bytes[i * 4 + 2] and padded_bytes[i * 4 + 3] are already 0
      end
      padded_bytes.pack('C*').force_encoding('BINARY')
    end

    # Perform AES SubBytes operation
    def self.sub_bytes(state)
      state.bytes.map { |b| SBOX[b] }.pack('C*')
    end

    # Perform inverse AES SubBytes operation
    def self.inv_sub_bytes(state)
      state.bytes.map { |b| INV_SBOX[b] }.pack('C*')
    end

    # Perform AES ShiftRows operation
    def self.shift_rows(state)
      bytes = state.bytes
      [
        bytes[0], bytes[5], bytes[10], bytes[15], bytes[4], bytes[9], bytes[14], bytes[3],
        bytes[8], bytes[13], bytes[2], bytes[7], bytes[12], bytes[1], bytes[6], bytes[11]
      ].pack('C*')
    end

    # Perform inverse AES ShiftRows operation
    def self.inv_shift_rows(state)
      bytes = state.bytes
      [
        bytes[0], bytes[13], bytes[10], bytes[7], bytes[4], bytes[1], bytes[14], bytes[11],
        bytes[8], bytes[5], bytes[2], bytes[15], bytes[12], bytes[9], bytes[6], bytes[3]
      ].pack('C*')
    end

    # Perform AES MixColumns operation
    def self.mix_columns(state)
      new_state = []
      4.times do |i|
        s = state[i * 4, 4].bytes
        s0, s1, s2, s3 = s
        new_state[i * 4] = MUL2[s0] ^ MUL3[s1] ^ s2 ^ s3
        new_state[i * 4 + 1] = s0 ^ MUL2[s1] ^ MUL3[s2] ^ s3
        new_state[i * 4 + 2] = s0 ^ s1 ^ MUL2[s2] ^ MUL3[s3]
        new_state[i * 4 + 3] = MUL3[s0] ^ s1 ^ s2 ^ MUL2[s3]
      end
      new_state.pack('C*')
    end

    # Perform inverse AES MixColumns operation
    def self.inv_mix_columns(state)
      new_state = []
      4.times do |i|
        col = state[i * 4, 4].bytes
        result = [
          gf_mul_0e(col[0]) ^ gf_mul_0b(col[1]) ^ gf_mul_0d(col[2]) ^ gf_mul_09(col[3]),
          gf_mul_09(col[0]) ^ gf_mul_0e(col[1]) ^ gf_mul_0b(col[2]) ^ gf_mul_0d(col[3]),
          gf_mul_0d(col[0]) ^ gf_mul_09(col[1]) ^ gf_mul_0e(col[2]) ^ gf_mul_0b(col[3]),
          gf_mul_0b(col[0]) ^ gf_mul_0d(col[1]) ^ gf_mul_09(col[2]) ^ gf_mul_0e(col[3])
        ]
        new_state += result
      end
      new_state.pack('C*')
    end

    # Encrypt using KIASU-BC construction
    def self.kiasu_bc_encrypt(key, tweak, plaintext)
      raise InvalidKeyError, 'Key must be 16 bytes' unless key.length == 16
      raise InvalidTweakError, 'Tweak must be 8 bytes' unless tweak.length == 8
      raise InvalidDataError, 'Plaintext must be 16 bytes' unless plaintext.length == 16

      round_keys = expand_key(key)
      padded_tweak = pad_tweak(tweak)

      # XOR plaintext with round key and padded tweak
      state = plaintext.bytes.zip(round_keys[0].bytes, padded_tweak.bytes)
                       .map { |p, k, t| p ^ k ^ t }.pack('C*')

      9.times do |i|
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        # XOR with round key and padded tweak
        state = state.bytes.zip(round_keys[i + 1].bytes, padded_tweak.bytes)
                     .map { |s, k, t| s ^ k ^ t }.pack('C*')
      end

      state = sub_bytes(state)
      state = shift_rows(state)
      # Final round - XOR with round key and padded tweak
      state.bytes.zip(round_keys[10].bytes, padded_tweak.bytes)
           .map { |s, k, t| s ^ k ^ t }.pack('C*')
    end

    # Decrypt using KIASU-BC construction
    def self.kiasu_bc_decrypt(key, tweak, ciphertext)
      raise InvalidKeyError, 'Key must be 16 bytes' unless key.length == 16
      raise InvalidTweakError, 'Tweak must be 8 bytes' unless tweak.length == 8
      raise InvalidDataError, 'Ciphertext must be 16 bytes' unless ciphertext.length == 16

      round_keys = expand_key(key)
      padded_tweak = pad_tweak(tweak)

      # Initial operations
      state = ciphertext.bytes.zip(round_keys[10].bytes, padded_tweak.bytes)
                        .map { |c, k, t| c ^ k ^ t }.pack('C*')
      state = inv_shift_rows(state)
      state = inv_sub_bytes(state)

      9.downto(1) do |i|
        # XOR with round key and padded tweak
        state = state.bytes.zip(round_keys[i].bytes, padded_tweak.bytes)
                     .map { |s, k, t| s ^ k ^ t }.pack('C*')
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
      end

      # Final round - XOR with round key and padded tweak
      state.bytes.zip(round_keys[0].bytes, padded_tweak.bytes)
           .map { |s, k, t| s ^ k ^ t }.pack('C*')
    end

    # Encrypt an IP address using ipcrypt-nd
    def self.encrypt(ip_address, key, tweak = nil)
      # Convert IP to bytes
      ip_bytes = ip_to_bytes(ip_address)

      # Use provided tweak or generate random 8-byte tweak
      if tweak.nil?
        tweak = OpenSSL::Random.random_bytes(8)
      elsif tweak.length != 8
        raise InvalidTweakError, 'Tweak must be 8 bytes'
      end

      # Encrypt using KIASU-BC
      ciphertext = kiasu_bc_encrypt(key, tweak, ip_bytes)

      # Return tweak || ciphertext
      tweak + ciphertext
    end

    # Decrypt an IP address using ipcrypt-nd
    def self.decrypt(encrypted_data, key)
      raise InvalidDataError, 'Encrypted data must be 24 bytes' unless encrypted_data.length == 24

      # Split into tweak and ciphertext
      tweak = encrypted_data[0, 8]
      ciphertext = encrypted_data[8, 16]

      # Decrypt using KIASU-BC
      ip_bytes = kiasu_bc_decrypt(key, tweak, ciphertext)

      # Convert back to IP address
      bytes_to_ip(ip_bytes)
    end
  end
end
