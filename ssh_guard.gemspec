# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run 'rake gemspec'
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{ssh_guard}
  s.version = "0.0.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Jelle Helsen"]
  s.date = %q{2010-12-02}
  s.default_executable = %q{ssh_guard}
  s.description = %q{It protects your server from ssh password guessing bots.}
  s.email = %q{jelle.helsen@hcode.be}
  s.executables = ["ssh_guard"]
  s.extra_rdoc_files = [
    "LICENSE.txt",
    "README.rdoc"
  ]
  s.files = [
    ".document",
    ".rspec",
    "Gemfile",
    "Gemfile.lock",
    "LICENSE.txt",
    "README.rdoc",
    "Rakefile",
    "VERSION",
    "autotest/discover.rb",
    "bin/ssh_guard",
    "lib/ssh_guard.rb",
    "lib/ssh_guard/database.rb",
    "lib/ssh_guard/firewall_adapters.rb",
    "spec/database_spec.rb",
    "spec/ipfw_adapter_spec.rb",
    "spec/spec_helper.rb",
    "spec/ssh_guard_spec.rb",
    "ssh_guard.gemspec"
  ]
  s.homepage = %q{http://github.com/jellehelsen/ssh_guard}
  s.licenses = ["MIT"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.7}
  s.summary = %q{guardian angel for ssh}
  s.test_files = [
    "spec/database_spec.rb",
    "spec/ipfw_adapter_spec.rb",
    "spec/spec_helper.rb",
    "spec/ssh_guard_spec.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<sequel>, [">= 0"])
      s.add_runtime_dependency(%q<sqlite3-ruby>, [">= 0"])
      s.add_development_dependency(%q<rspec>, ["~> 2.1.0"])
      s.add_development_dependency(%q<bundler>, ["~> 1.0.0"])
      s.add_development_dependency(%q<jeweler>, ["~> 1.5.1"])
      s.add_development_dependency(%q<rcov>, [">= 0"])
    else
      s.add_dependency(%q<sequel>, [">= 0"])
      s.add_dependency(%q<sqlite3-ruby>, [">= 0"])
      s.add_dependency(%q<rspec>, ["~> 2.1.0"])
      s.add_dependency(%q<bundler>, ["~> 1.0.0"])
      s.add_dependency(%q<jeweler>, ["~> 1.5.1"])
      s.add_dependency(%q<rcov>, [">= 0"])
    end
  else
    s.add_dependency(%q<sequel>, [">= 0"])
    s.add_dependency(%q<sqlite3-ruby>, [">= 0"])
    s.add_dependency(%q<rspec>, ["~> 2.1.0"])
    s.add_dependency(%q<bundler>, ["~> 1.0.0"])
    s.add_dependency(%q<jeweler>, ["~> 1.5.1"])
    s.add_dependency(%q<rcov>, [">= 0"])
  end
end

