#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'lib/ipcrypt'
require_relative 'lib/ipcrypt/deterministic'
require_relative 'lib/ipcrypt/nd'
require_relative 'lib/ipcrypt/ndx'

# Example usage
puts 'IPCrypt Examples'
puts '==============='

# Deterministic example
puts "\n1. Deterministic Encryption (ipcrypt-deterministic)"
key1 = '0123456789abcdeffedcba9876543210'.scan(/../).map(&:hex).pack('C*')
ip1 = '192.0.2.1'
encrypted1 = IPCrypt::Deterministic.encrypt(ip1, key1)
decrypted1 = IPCrypt::Deterministic.decrypt(encrypted1, key1)
puts "Original IP: #{ip1}"
puts "Encrypted IP: #{encrypted1}"
puts "Decrypted IP: #{decrypted1}"
puts "Match: #{ip1 == decrypted1.to_s}"

# ND example
puts "\n2. Non-Deterministic Encryption (ipcrypt-nd)"
key2 = '0123456789abcdeffedcba9876543210'.scan(/../).map(&:hex).pack('C*')
ip2 = '192.0.2.1'
tweak2 = '08e0c289bff23b7c'.scan(/../).map(&:hex).pack('C*')
encrypted2 = IPCrypt::ND.encrypt(ip2, key2, tweak2)
decrypted2 = IPCrypt::ND.decrypt(encrypted2, key2)
puts "Original IP: #{ip2}"
puts "Encrypted data (hex): #{encrypted2.unpack1('H*')}"
puts "Decrypted IP: #{decrypted2}"
puts "Match: #{ip2 == decrypted2.to_s}"

# NDX example
puts "\n3. Non-Deterministic Encryption XTS (ipcrypt-ndx)"
key3 = '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301'.scan(/../).map(&:hex).pack('C*')
ip3 = '192.0.2.1'
tweak3 = '21bd1834bc088cd2b4ecbe30b70898d7'.scan(/../).map(&:hex).pack('C*')
ip_bytes3 = IPCrypt::NDX.ip_to_bytes(ip3)
ciphertext3 = IPCrypt::NDX.aes_xts_encrypt(key3, tweak3, ip_bytes3)
encrypted3 = tweak3 + ciphertext3
decrypted3 = IPCrypt::NDX.decrypt(encrypted3, key3)
puts "Original IP: #{ip3}"
puts "Encrypted data (hex): #{encrypted3.unpack1('H*')}"
puts "Decrypted IP: #{decrypted3}"
puts "Match: #{ip3 == decrypted3.to_s}"
