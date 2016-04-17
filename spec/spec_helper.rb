$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'arachni/debug/rack'

require 'ap'
require 'pp'
require 'rack/test'

require_relative 'support/helpers/paths'

Dir.glob( "#{support_path}/{lib,helpers,shared,factories,fixtures}/**/*.rb" ).each { |f| require f }
