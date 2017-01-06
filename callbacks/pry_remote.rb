=begin

    This file is part of the Arachni::Debug::Rack project and may be subject to
    redistribution and commercial restrictions. Please see the Arachni::Debug::Rack
    web site for more information on licensing and terms of use.

=end

require 'pry-remote'

binding.remote_pry( *[options[:host], options[:port]].compact )
