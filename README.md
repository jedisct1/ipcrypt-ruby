# IPCrypt2 Ruby Implementation

A Ruby implementation of the IPCrypt specification for encrypting and obfuscating IP addresses, as defined in the [IPCrypt IETF draft](https://datatracker.ietf.org/doc/draft-denis-ipcrypt/).

This gem provides privacy-preserving methods for storing, logging, and analyzing IP addresses while maintaining the ability to decrypt them when necessary.

## Features

- **Four encryption modes:**
  - `ipcrypt-deterministic`: Deterministic encryption using AES-128 (same input always produces same output)
  - `ipcrypt-pfx`: Prefix-preserving encryption that maintains network relationships while encrypting addresses
  - `ipcrypt-nd`: Non-deterministic encryption using KIASU-BC with 8-byte tweak
  - `ipcrypt-ndx`: Non-deterministic encryption using AES-XTS with 16-byte tweak
- **Full IPv4 and IPv6 support** with automatic conversion to unified 16-byte format
- **Prefix preservation** with ipcrypt-pfx for network-level analytics while protecting individual addresses
- **Secure implementations** using OpenSSL for cryptographic operations
- **Comprehensive test suite** with official test vectors from the specification
- **Ruby 2.6+ compatibility**

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ipcrypt2'
```

And then execute:

```bash
$ bundle install
```

Or install it yourself as:

```bash
$ gem install ipcrypt2
```

## Usage

### Deterministic Encryption (ipcrypt-deterministic)

```ruby
require 'ipcrypt/deterministic'

# 16-byte key
key = "0123456789abcdeffedcba9876543210".scan(/../).map { |x| x.hex }.pack("C*")

# Encrypt an IP address
ip = "192.0.2.1"
encrypted_ip = IPCrypt::Deterministic.encrypt(ip, key)
decrypted_ip = IPCrypt::Deterministic.decrypt(encrypted_ip, key)
```

### Non-Deterministic Encryption with KIASU-BC (ipcrypt-nd)

```ruby
require 'ipcrypt/nd'

# 16-byte key
key = "0123456789abcdeffedcba9876543210".scan(/../).map { |x| x.hex }.pack("C*")

# Encrypt an IP address (with optional tweak)
ip = "192.0.2.1"
encrypted_data = IPCrypt::ND.encrypt(ip, key)  # Random tweak
# or
tweak = "08e0c289bff23b7c".scan(/../).map { |x| x.hex }.pack("C*")
encrypted_data = IPCrypt::ND.encrypt(ip, key, tweak)  # Specific tweak

# Decrypt
decrypted_ip = IPCrypt::ND.decrypt(encrypted_data, key)
```

### Prefix-Preserving Encryption (ipcrypt-pfx)

```ruby
require 'ipcrypt/pfx'

# 32-byte key (split into two AES-128 keys internally)
key = "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301".scan(/../).map { |x| x.hex }.pack("C*")

# Encrypt IP addresses - addresses from the same network share encrypted prefix
ip1 = "10.0.0.1"
ip2 = "10.0.0.2"
encrypted_ip1 = IPCrypt::Pfx.encrypt(ip1, key)  # "154.135.56.208"
encrypted_ip2 = IPCrypt::Pfx.encrypt(ip2, key)  # "154.135.56.211" (same /24 prefix)

# Decrypt
decrypted_ip1 = IPCrypt::Pfx.decrypt(encrypted_ip1, key)  # Returns "10.0.0.1"
```

### Non-Deterministic Encryption with AES-XTS (ipcrypt-ndx)

```ruby
require 'ipcrypt/ndx'

# 32-byte key
key = "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301".scan(/../).map { |x| x.hex }.pack("C*")

# Encrypt an IP address
ip = "192.0.2.1"
encrypted_data = IPCrypt::NDX.encrypt(ip, key)

# Decrypt
decrypted_ip = IPCrypt::NDX.decrypt(encrypted_data, key)
```

## Framework Integration

### Ruby on Rails

#### 1. Basic Setup

Add to your `Gemfile`:

```ruby
gem 'ipcrypt2'
```

Create an initializer `config/initializers/ipcrypt.rb`:

```ruby
# Store your key securely using Rails credentials
Rails.application.config.ipcrypt_key = Rails.application.credentials.ipcrypt_key

# Or use environment variables
Rails.application.config.ipcrypt_key = ENV['IPCRYPT_KEY'].scan(/../).map { |x| x.hex }.pack("C*")
```

#### 2. ActiveRecord Model Integration

```ruby
class User < ApplicationRecord
  # Store encrypted IP addresses in the database

  def ip_address=(ip)
    key = Rails.application.config.ipcrypt_key
    self.encrypted_ip = IPCrypt::Deterministic.encrypt(ip, key)
  end

  def ip_address
    return nil unless encrypted_ip.present?
    key = Rails.application.config.ipcrypt_key
    IPCrypt::Deterministic.decrypt(encrypted_ip, key)
  end
end
```

#### 3. Request Logging

Create a concern for controllers:

```ruby
# app/controllers/concerns/ip_encryption.rb
module IpEncryption
  extend ActiveSupport::Concern

  included do
    before_action :store_encrypted_ip
  end

  private

  def store_encrypted_ip
    return unless request.remote_ip.present?

    key = Rails.application.config.ipcrypt_key
    encrypted_ip = IPCrypt::Deterministic.encrypt(request.remote_ip, key)

    # Store in session, database, or logs
    session[:encrypted_ip] = encrypted_ip
  end
end

# Use in controllers
class ApplicationController < ActionController::Base
  include IpEncryption
end
```

#### 4. Custom Logger

```ruby
# config/application.rb
class EncryptedIpLogger < ActiveSupport::Logger
  def add_ip(severity, ip_address, progname = nil)
    key = Rails.application.config.ipcrypt_key
    encrypted_ip = IPCrypt::Deterministic.encrypt(ip_address, key)
    add(severity, "IP: #{encrypted_ip}", progname)
  end
end

# Usage
Rails.logger.add_ip(Logger::INFO, request.remote_ip)
```

### Sinatra

```ruby
require 'sinatra'
require 'ipcrypt/deterministic'

configure do
  set :ipcrypt_key, ENV['IPCRYPT_KEY'].scan(/../).map { |x| x.hex }.pack("C*")
end

helpers do
  def encrypt_ip(ip)
    IPCrypt::Deterministic.encrypt(ip, settings.ipcrypt_key)
  end

  def decrypt_ip(encrypted_ip)
    IPCrypt::Deterministic.decrypt(encrypted_ip, settings.ipcrypt_key)
  end
end

before do
  @encrypted_client_ip = encrypt_ip(request.ip)
end

get '/' do
  "Your encrypted IP: #{@encrypted_client_ip}"
end
```

### Rack Middleware

Create middleware for any Rack-based application:

```ruby
# lib/rack/ip_encryptor.rb
module Rack
  class IpEncryptor
    def initialize(app, key)
      @app = app
      @key = key
    end

    def call(env)
      # Encrypt the client IP
      if env['REMOTE_ADDR']
        env['rack.encrypted_ip'] = IPCrypt::Deterministic.encrypt(env['REMOTE_ADDR'], @key)
      end

      @app.call(env)
    end
  end
end

# Usage in config.ru
require 'ipcrypt/deterministic'

key = ENV['IPCRYPT_KEY'].scan(/../).map { |x| x.hex }.pack("C*")
use Rack::IpEncryptor, key
run YourApp
```

### Hanami

```ruby
# config/environment.rb
require 'ipcrypt/deterministic'

Hanami.configure do
  # Store key in settings
  settings.ipcrypt_key = ENV['IPCRYPT_KEY'].scan(/../).map { |x| x.hex }.pack("C*")
end

# app/actions/application.rb
module YourApp
  module Actions
    class Application < Hanami::Action
      before :encrypt_client_ip

      private

      def encrypt_client_ip
        return unless request.ip

        key = Hanami.app.settings.ipcrypt_key
        @encrypted_ip = IPCrypt::Deterministic.encrypt(request.ip, key)
      end
    end
  end
end
```

### Grape API

```ruby
require 'grape'
require 'ipcrypt/deterministic'

class API < Grape::API
  helpers do
    def ipcrypt_key
      @key ||= ENV['IPCRYPT_KEY'].scan(/../).map { |x| x.hex }.pack("C*")
    end

    def encrypted_client_ip
      IPCrypt::Deterministic.encrypt(request.ip, ipcrypt_key)
    end
  end

  before do
    # Log encrypted IP for each request
    logger.info "Request from: #{encrypted_client_ip}"
  end

  get '/my-ip' do
    { encrypted_ip: encrypted_client_ip }
  end
end
```

## Best Practices

1. **Key Management**: Never hardcode encryption keys. Use environment variables or secure credential stores like Rails credentials.

2. **Choose the Right Mode**:
   - Use `deterministic` for logs and analytics where you need to correlate multiple requests from the same IP
   - Use `pfx` for network-level analytics where you need to preserve subnet relationships while encrypting individual addresses
   - Use `nd` or `ndx` for storage where each encryption should be unique

3. **Performance**: For high-traffic applications, consider caching the key parsing:
   ```ruby
   class IpEncryptor
     def self.key
       @key ||= ENV['IPCRYPT_KEY'].scan(/../).map { |x| x.hex }.pack("C*")
     end
   end
   ```

4. **Database Storage**: Store encrypted IPs as binary or base64-encoded strings:
   ```ruby
   # Migration
   add_column :users, :encrypted_ip, :binary

   # Model
   def ip_address=(ip)
     self.encrypted_ip = IPCrypt::Deterministic.encrypt(ip, key)
   end
   ```

## Development

After checking out the repo, run `bundle install` to install dependencies.

### Running Tests

```bash
# Run all tests
bundle exec rake test

# Run tests with verbose output
bundle exec rake test_verbose

# Run RuboCop linting
bundle exec rubocop

# Run both tests and linting (default task)
bundle exec rake
```

### Building the Gem

```bash
# Build the gem
gem build ipcrypt2.gemspec

# Install locally for testing
gem install ./ipcrypt2-*.gem
```
