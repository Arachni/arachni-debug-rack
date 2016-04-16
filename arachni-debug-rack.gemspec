# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'arachni/debug/rack/version'

Gem::Specification.new do |spec|
    spec.name    = 'arachni-debug-rack'
    spec.version = Arachni::Debug::Rack::VERSION
    spec.authors = ['Tasos Laskos']
    spec.email   = ['tasos.laskos@arachni-scanner.com']

    spec.summary     = %q{
        Allows debugging of issues idenified by Arachni in Rack-based web applications (Rails, Sinatra, etc.).
    }
    spec.homepage    = 'https://github.com/Arachni/arachni-debug-rack'

    spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
    spec.bindir        = 'bin'
    spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
    spec.require_paths = ['lib']

    spec.add_development_dependency 'sinatra'
    spec.add_development_dependency 'awesome_print'
    spec.add_development_dependency 'better_errors'
    spec.add_development_dependency 'pry'
    spec.add_development_dependency 'pry-remote'
    spec.add_development_dependency 'puma'
    spec.add_development_dependency 'bundler',  '~> 1.11'
    spec.add_development_dependency 'rake',     '~> 10.0'
    spec.add_development_dependency 'rspec',    '~> 3.0'
end
