require 'pry-remote'

binding.remote_pry( *[options[:host], options[:port]].compact )
