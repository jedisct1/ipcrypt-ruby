# frozen_string_literal: true

# Main module for IPCrypt implementations
module IPCrypt
  class Error < StandardError; end
  class InvalidKeyError < Error; end
  class InvalidTweakError < Error; end
  class InvalidDataError < Error; end
end

require_relative 'ipcrypt/deterministic'
require_relative 'ipcrypt/nd'
require_relative 'ipcrypt/ndx'
require_relative 'ipcrypt/pfx'
require_relative 'ipcrypt/version'
