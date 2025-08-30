# frozen_string_literal: true

require_relative 'lib/ipcrypt/version'

Gem::Specification.new do |spec|
  spec.name          = 'ipcrypt2'
  spec.version       = IPCrypt::VERSION
  spec.authors       = ['Frank Denis']
  spec.email         = ['fde@00f.net']

  spec.summary       = 'Ruby implementation of IPCrypt for encrypting and obfuscating IP addresses'
  spec.description   = 'IPCrypt provides methods for encrypting and obfuscating IP addresses ' \
                       'for privacy-preserving storage, logging, and analytics. Implements ' \
                       'deterministic, non-deterministic (KIASU-BC), and XTS-based encryption.'
  spec.homepage      = 'https://github.com/jedisct1/ipcrypt-ruby'
  spec.license       = 'MIT'

  spec.required_ruby_version = '>= 2.6.0'
  spec.metadata = {
    'homepage_uri' => spec.homepage,
    'source_code_uri' => 'https://github.com/jedisct1/ipcrypt-ruby',
    'changelog_uri' => 'https://github.com/jedisct1/ipcrypt-ruby/blob/master/CHANGELOG.md',
    'bug_tracker_uri' => 'https://github.com/jedisct1/ipcrypt-ruby/issues',
    'documentation_uri' => 'https://www.rubydoc.info/gems/ipcrypt2'
  }

  spec.files         = Dir['lib/**/*', 'README.md', 'LICENSE', 'CHANGELOG.md']
  spec.bindir        = 'exe'
  spec.executables   = []
  spec.require_paths = ['lib']

  spec.add_development_dependency 'minitest', '~> 5.0'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rubocop', '~> 1.0'
end
