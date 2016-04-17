require 'arachni/debug/rack'
require 'sinatra/base'

class MockApp < Sinatra::Base

    use Arachni::Debug::Rack::Middleware,
        scope:    __dir__,
        callback: {
            name:    "#{__dir__}/mock_callback",
            options: {
                blah: 'stuff'
            }
        }


    get '/' do
        <<EOHTML
    <a href="/xss?a=b">XSS</a>
EOHTML
    end

    get '/xss' do
        params[:a]
    end

end

