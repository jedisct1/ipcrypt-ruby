# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rake/testtask'
require 'rubocop/rake_task'

Rake::TestTask.new(:test) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/**/test_*.rb']
  t.verbose = true
end

RuboCop::RakeTask.new

task default: %i[test rubocop]

desc 'Run tests with verbose output'
task :test_verbose do
  ENV['VERBOSE'] = '1'
  Rake::Task['test'].invoke
end

desc 'Generate and verify test vectors'
task :verify_vectors do
  sh 'ruby test/test_ipcrypt.rb'
end

desc 'Build the gem'
task :build do
  sh 'gem build ipcrypt2.gemspec'
end

desc 'Install the gem locally'
task install: :build do
  sh "gem install ./ipcrypt2-#{IPCrypt::VERSION}.gem"
end

desc 'Clean up generated files'
task :clean do
  sh 'rm -f *.gem'
  sh 'rm -rf coverage'
  sh 'rm -rf pkg'
end
