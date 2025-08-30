# frozen_string_literal: true

require 'minitest/autorun'
require 'json'
require 'openssl'
require 'ipaddr'
require_relative '../lib/ipcrypt'
require_relative '../lib/ipcrypt/deterministic'
require_relative '../lib/ipcrypt/nd'
require_relative '../lib/ipcrypt/ndx'

class TestIPCrypt < Minitest::Test
  def setup
    # Load test vectors
    test_vectors_file = File.join(File.dirname(__FILE__), '..', '..', 'python', 'test_vectors.json')
    @test_vectors = JSON.parse(File.read(test_vectors_file))
  end

  def test_deterministic_vectors
    @test_vectors.select { |v| v['variant'] == 'ipcrypt-deterministic' }.each do |vector|
      key = [vector['key']].pack('H*')
      ip = vector['ip']
      expected_encrypted_ip = vector['encrypted_ip']

      # Encrypt
      encrypted_ip = IPCrypt::Deterministic.encrypt(ip, key)
      assert_equal expected_encrypted_ip, encrypted_ip.to_s,
                   "Failed to encrypt #{ip} with key #{vector['key']}"

      # Decrypt
      decrypted_ip = IPCrypt::Deterministic.decrypt(encrypted_ip, key)
      # For IPv4 addresses, we should get back the original IPv4 format
      expected_result = IPAddr.new(ip)
      assert_equal expected_result, decrypted_ip,
                   "Failed to decrypt #{encrypted_ip} with key #{vector['key']}"
    end
  end

  def test_nd_vectors
    @test_vectors.select { |v| v['variant'] == 'ipcrypt-nd' }.each do |vector|
      key = [vector['key']].pack('H*')
      ip = vector['ip']
      tweak = [vector['tweak']].pack('H*')
      expected_output = [vector['output']].pack('H*')

      # Encrypt with specific tweak
      output = IPCrypt::ND.encrypt(ip, key, tweak)
      assert_equal expected_output, output,
                   "Failed to encrypt #{ip} with key #{vector['key']} and tweak #{vector['tweak']}"

      # Decrypt
      decrypted_ip = IPCrypt::ND.decrypt(output, key)
      # For IPv4 addresses, we should get back the original IPv4 format
      expected_result = IPAddr.new(ip)
      assert_equal expected_result, decrypted_ip,
                   "Failed to decrypt output with key #{vector['key']}"
    end
  end

  def test_ndx_vectors
    @test_vectors.select { |v| v['variant'] == 'ipcrypt-ndx' }.each do |vector|
      key = [vector['key']].pack('H*')
      ip = vector['ip']
      tweak = [vector['tweak']].pack('H*')
      expected_output = [vector['output']].pack('H*')

      # Encrypt with specific tweak
      # For NDX, we need to manually construct the output since we're using a fixed tweak
      ip_bytes = IPCrypt::NDX.ip_to_bytes(ip)
      ciphertext = IPCrypt::NDX.aes_xts_encrypt(key, tweak, ip_bytes)
      output = tweak + ciphertext

      assert_equal expected_output, output,
                   "Failed to encrypt #{ip} with key #{vector['key']} and tweak #{vector['tweak']}"

      # Decrypt
      decrypted_ip = IPCrypt::NDX.decrypt(output, key)
      # For IPv4 addresses, we should get back the original IPv4 format
      expected_result = IPAddr.new(ip)
      assert_equal expected_result, decrypted_ip,
                   "Failed to decrypt output with key #{vector['key']}"
    end
  end

  def test_round_trip_deterministic
    key = OpenSSL::Random.random_bytes(16)
    ips = ['192.0.2.1', '2001:db8::1', '0.0.0.0', '255.255.255.255']

    ips.each do |ip|
      encrypted = IPCrypt::Deterministic.encrypt(ip, key)
      decrypted = IPCrypt::Deterministic.decrypt(encrypted, key)
      expected_result = IPAddr.new(ip)
      assert_equal expected_result, decrypted, "Round-trip failed for #{ip}"
    end
  end

  def test_round_trip_nd
    key = OpenSSL::Random.random_bytes(16)
    ips = ['192.0.2.1', '2001:db8::1', '0.0.0.0', '255.255.255.255']

    ips.each do |ip|
      encrypted = IPCrypt::ND.encrypt(ip, key)
      decrypted = IPCrypt::ND.decrypt(encrypted, key)
      expected_result = IPAddr.new(ip)
      assert_equal expected_result, decrypted, "Round-trip failed for #{ip}"
    end
  end

  def test_round_trip_ndx
    key = OpenSSL::Random.random_bytes(32)
    ips = ['192.0.2.1', '2001:db8::1', '0.0.0.0', '255.255.255.255']

    ips.each do |ip|
      encrypted = IPCrypt::NDX.encrypt(ip, key)
      decrypted = IPCrypt::NDX.decrypt(encrypted, key)
      expected_result = IPAddr.new(ip)
      assert_equal expected_result, decrypted, "Round-trip failed for #{ip}"
    end
  end

  def test_invalid_key_lengths
    ip = '192.0.2.1'

    # Deterministic - should be 16 bytes
    assert_raises(IPCrypt::InvalidKeyError) do
      IPCrypt::Deterministic.encrypt(ip, 'short_key')
    end

    # ND - should be 16 bytes
    assert_raises(IPCrypt::InvalidKeyError) do
      IPCrypt::ND.encrypt(ip, 'short_key')
    end

    # NDX - should be 32 bytes
    assert_raises(IPCrypt::InvalidKeyError) do
      IPCrypt::NDX.encrypt(ip, 'short_key')
    end
  end

  def test_invalid_tweak_lengths
    ip = '192.0.2.1'
    key = OpenSSL::Random.random_bytes(16)

    # ND - tweak should be 8 bytes
    assert_raises(IPCrypt::InvalidTweakError) do
      IPCrypt::ND.encrypt(ip, key, 'short_tweak')
    end
  end
end
