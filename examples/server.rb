require 'arachni/debug/rack'
require 'sinatra'

use Arachni::Debug::Rack::Middleware,
    scope:    __dir__,
    callback: {
        name: 'pry'
    }

get '/' do
    <<EOHTML
    <a href="/xss?a=b">XSS</a>
EOHTML
end

get '/xss' do
    params[:a]
end
