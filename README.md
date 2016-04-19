# arachni-debug-rack

Allows debugging of vulnerabilities identified by [Arachni](http://www.arachni-scanner.com)
in [Rack](https://github.com/rack/rack)-based web applications ([Rails](http://rubyonrails.org/),
[Sinatra](http://sinatrarb.com/), etc.) by running user specified code upon issue reproduction.

The process goes something like this:

* Install `arachni-debug-rack` in web application.
  * Set desired callback.
    * [IRB](https://en.wikipedia.org/wiki/Interactive_Ruby_Shell)
    * [Pry](https://github.com/pry/pry/)
      * [Remote](https://github.com/Mon-Ouie/pry-remote) as well.
    * [Better errors](https://github.com/charliesome/better_errors/) -- pending.
    * External Ruby scripts.
* Run Arachni scan.
* Run `arachni_reproduce` with the scan report and specify desired issue.
  * Replays issue.
  * Triggers server-side callback.
  * **DEBUG**: The callback runs under the vulnerable state of web application,
    thus allowing for the issue to be debugged.

**Still in alpha phase, may break compatibility (or altogether) without warning.**

## Installation

Add the following to your web application's `Gemfile`:

```ruby
gem 'arachni-debug-rack', github: 'Arachni/arachni-debug-rack'
```

Then run `bundle install`.

Setup the middleware:

```ruby
require 'arachni/debug/rack'

use Arachni::Debug::Rack::Middleware,
    # Only track execution of code in files under this directory and its children.
    # You probably want to set this to your application's root directory.
    scope:    __dir__, # Optional

    # Mandatory callback configuration, needs at least a name.
    callback: {
        # Launch 'irb' in the terminal of the web application.
        name:    'irb'

        # Launch 'pry' in the terminal of the web application.
        # You need to install 'pry' yourself.
        # name:    'pry'

        # Launch a 'pry' server, accessible using 'pry-remote'.
        # You need to install 'pry-remote' yourself.
        # name:    'callbacks/pry_remote.rb',
        # options: {             # Optional
        #     host: '127.0.0.2', # Optional
        #     port: 9999         # Optional
        # }

        # Load an external script to run under the middleware context, with
        # access to all relevant trace points and bindings.
        # name:    '/path/to/external/script.rb',
        # You can also pass options to your script, accessible via the
        # `options` variable.
        # options: {           # Optional
        #     random: 'option' # Optional
        # }
    }
```

## Usage

You can try these instructions with the provided
[example Sinatra application](https://github.com/Arachni/arachni-debug-rack/blob/master/examples/server.rb):

    # We could just use IRB for these examples, but 'pry' will really drive this home.
    gem install pry
    bundle exec ruby examples/server.rb -o 0.0.0.0

### Without Arachni

This project is meant to be used to debug vulnerabilities identified by Arachni,
but the server-side callbacks can be triggered by any request so long as it sets
the `X-Arachni-Issue-Digest` header.

That `X-Arachni-Issue-Digest` header is meant to be a numeric checksum used to
uniquely identify issues logged by Arachni.

For example:

    $ curl http://127.0.0.2:4567/?myparam=myval -H X-Arachni-Issue-Digest:12345
        <a href="/xss?a=b">XSS</a>

And on the server side:

    127.0.0.1 - - [16/Apr/2016:23:30:16 +0300] "GET /?myparam=myval HTTP/1.1" 200 31 0.0116
    [1] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points
    ============================== Request #1 -- 12345
    0: [2016-04-16 23:30:16 +0300] examples/server.rb:10 Sinatra::Application#GET / call in Sinatra::Application#GET /
    1: [2016-04-16 23:30:16 +0300] examples/server.rb:10 Sinatra::Application#GET / b_call in Sinatra::Application#GET /
    2: [2016-04-16 23:30:16 +0300] examples/server.rb:11 Sinatra::Application#GET / line in Sinatra::Application#GET /
    3: [2016-04-16 23:30:16 +0300] examples/server.rb:14 Sinatra::Application#GET / b_return in Sinatra::Application#GET /
    => nil
    [2] pry(#<Arachni::Debug::Rack::Middleware>)> trace_points_for_request_id(1).first[:binding].pry

    From: /home/zapotek/workspace/arachni-debug-rack/examples/server.rb @ line 10 self.GET /:

         5:     scope:    __dir__,
         6:     callback: {
         7:         name: 'pry'
         8:     }
         9:
     => 10: get '/' do
        11:     <<EOHTML
        12:     <a href="/xss?a=b">XSS</a>
        13: EOHTML
        14: end
        15:

    [1] pry(#<Sinatra::Application>)> __method__
    => :"GET /"
    [2] pry(#<Sinatra::Application>)> params
    => {"myparam"=>"myval"}
    [3] pry(#<Sinatra::Application>)>

As you can see, the Pry console was launched and we were able to do some pretty
cool stuff with it.

### With Arachni

When used with Arachni it is possible to load scan reports and specify issues
to debug.

For this we'll need to use one of the [nightly packages](http://downloads.arachni-scanner.com/nightlies/),
just extract the archive and switch to the package directory.

#### Step 1

Scan the web application and get your hands on the resulting AFR report, for example:

    ./bin/arachni http://127.0.0.2:4567/ --checks xss --browser-cluster-pool-size=0 --report-save-path=report.afr

`report.afr` is the file we want.

#### Step 2

Copy the `Digest` of the issue you'd like to debug, which you can find towards the
top of each issue printout:

    [+] [1] Cross-Site Scripting (XSS) (Trusted)
    [~] ~~~~~~~~~~~~~~~~~~~~
    [~] Digest:     2593139878
    [~] Severity:   High

In this case we only have one issue, with a digest of `2593139878`.

_This information is included in all report formats._

#### Step 3

Pass the report and the issue digest to `arachni_reproduce`, like so:

    ./bin/arachni_reproduce report.afr 2593139878

You should then see something like:

    Arachni - Web Application Security Scanner Framework v2.0dev
       Author: Tasos "Zapotek" Laskos <tasos.laskos@arachni-scanner.com>

               (With the support of the community and the Arachni Team.)

       Website:       http://arachni-scanner.com
       Documentation: http://arachni-scanner.com/wiki


     [~] ============================ (1/1) [2593139878] Cross-Site Scripting (XSS) in link input "a" =============================
     [~] ============================================== From: http://127.0.0.2:4567/ ==============================================
     [~] ============= At: http://127.0.0.2:4567/xss?a=b%3Csome_dangerous_input_98d7aa6d71454cb9932cf329b7d29314/%3E ==============
     [~] ============================ Using: b<some_dangerous_input_98d7aa6d71454cb9932cf329b7d29314/> ============================


     [*] ------------------------------------------------------ Reproducing -------------------------------------------------------

     [*] Preparing plugins...
     [*] ... done.

     [*] [HTTP: 200] http://127.0.0.2:4567/
     [~] DOM depth: 0 (Limit: 5)
     [*] XSS: Auditing link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [*] XSS: Auditing link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [*] XSS: Auditing link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [*] XSS: Auditing link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [*] XSS: Auditing link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [*] XSS: Auditing link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [*] Harvesting HTTP responses...
     [~] Depending on server responsiveness and network conditions this may take a while.
     [*] XSS: Analyzing response #2 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [+] XSS: In link input 'a' with action http://127.0.0.2:4567/xss
     [*] XSS: Analyzing response #0 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [+] XSS: In link input 'a' with action http://127.0.0.2:4567/xss
     [*] XSS: Analyzing response #1 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [*] XSS: Analyzing response #3 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [*] XSS: Analyzing response #4 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [+] XSS: In link input 'a' with action http://127.0.0.2:4567/xss
     [*] XSS: Analyzing response #5 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'


     [~] ------------------------------------------------------- Issue seed -------------------------------------------------------
     [~] You can use this to identify a narrow scope of tainted inputs (params, cookies, etc.) and sinks (response bodies, SQL
     [~] queries etc.) related to this issue.
     [~] It is accessible via the 'X-Arachni-Issue-Seed' header.

    ()"&%1'-;<some_dangerous_input_f8baed11acb08093b3a4b24a30393c0a/>'

     [~] --------------------------------------------------------- Proof ----------------------------------------------------------

    <some_dangerous_input_f8baed11acb08093b3a4b24a30393c0a/>

     [~] -------------------------------------------------------- Request ---------------------------------------------------------

    GET /xss?a=b%28%29%22%26%251%27-%3B%3Csome_dangerous_input_f8baed11acb08093b3a4b24a30393c0a%2F%3E%27 HTTP/1.1
    Host: 127.0.0.2:4567
    Accept-Encoding: gzip, deflate
    User-Agent: Arachni/v2.0dev
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.8,he;q=0.6
    X-Arachni-Scan-Seed: f8baed11acb08093b3a4b24a30393c0a
    X-Arachni-Issue-Replay-Id: f3136422cbc231e31c9d4ccbe0107e26
    X-Arachni-Issue-Seed: ()"&%1'-;<some_dangerous_input_f8baed11acb08093b3a4b24a30393c0a/>'
    X-Arachni-Issue-Digest: 2593139878


     [~] -------------------------------------------------------- Response ---------------------------------------------------------

    HTTP/1.1 200 OK
    Content-Type: text/html;charset=utf-8
    X-XSS-Protection: 1; mode=block
    X-Content-Type-Options: nosniff
    X-Frame-Options: SAMEORIGIN
    Content-Length: 67


     [+] ================================================== Reproduced 1 issues ===================================================
     [~] These issues were successfully replayed.

     [+] [2593139878] Cross-Site Scripting (XSS) in link input 'a'
     [~]   From:  http://127.0.0.2:4567/
     [~]   At:    http://127.0.0.2:4567/xss?a=b()%22%26%251'-;%3Csome_dangerous_input_f8baed11acb08093b3a4b24a30393c0a/%3E'
     [~]   Using: b()"&%1'-;<some_dangerous_input_f8baed11acb08093b3a4b24a30393c0a/>'


     [-] ==================================================== Missing 0 issues ====================================================
     [~] All issues were successfully replayed.


     [~] ===================================================== Updated report =====================================================
     [~] Report with reproduced issues saved at:
     [~]     /home/zapotek/workspace/arachni/127.0.0.2 2016-04-19 21_49_58 +0300.afr

     [~] ======================================================= Scan seed ========================================================
     [~] You can use this to identify tainted inputs (params, cookies, etc.) and sinks (response bodies, SQL queries etc.).
     [~] It is accessible via the 'X-Arachni-Scan-Seed' header.

     [~] f8baed11acb08093b3a4b24a30393c0a

#### Step 4

**Tada!**

If you step over to the terminal of your web application, you'll see a Pry prompt
waiting for you, something like:

    127.0.0.1 - - [19/Apr/2016:21:51:56 +0300] "GET /xss?a=b%253C%252Ftextarea%253E--%253E%253Csome_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88%252F%253E%253C%2521--%253Ctextarea%253E HTTP/1.1" 200 107 0.0029
    127.0.0.1 - - [19/Apr/2016:21:51:56 +0300] "GET /xss?a=b%28%29%22%26%251%27-%3B%3Csome_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88%2F%3E%27 HTTP/1.1" 200 67 0.0004
    127.0.0.1 - - [19/Apr/2016:21:51:56 +0300] "GET /xss?a=b%3C%2Ftextarea%3E--%3E%3Csome_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88%2F%3E%3C%21--%3Ctextarea%3E HTTP/1.1" 200 85 0.0002
    127.0.0.1 - - [19/Apr/2016:21:51:56 +0300] "GET /xss?a=b%253Csome_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88%252F%253E HTTP/1.1" 200 63 0.0004
    127.0.0.1 - - [19/Apr/2016:21:51:56 +0300] "GET /xss?a=b%3Csome_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88%2F%3E HTTP/1.1" 200 57 0.0030
    127.0.0.1 - - [19/Apr/2016:21:51:56 +0300] "GET /xss?a=b%2528%2529%2522%2526%25251%2527-%253B%253Csome_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88%252F%253E%2527 HTTP/1.1" 200 89 0.0002
    127.0.0.1 - - [19/Apr/2016:21:51:56 +0300] "GET /xss?a=b%28%29%22%26%251%27-%3B%3Csome_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88%2F%3E%27 HTTP/1.1" 200 67 0.0094
    [1] pry(#<Arachni::Debug::Rack::Middleware>)>

We're now operating under the context of the middleware, see:

    [1] pry(#<Arachni::Debug::Rack::Middleware>)> env
    => {"rack.version"=>[1, 3],
     "rack.errors"=>#<IO:<STDERR>>,
     "rack.multithread"=>true,
     "rack.multiprocess"=>false,
     "rack.run_once"=>false,
     "SCRIPT_NAME"=>"",
     "QUERY_STRING"=>"a=b%28%29%22%26%251%27-%3B%3Csome_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88%2F%3E%27",
     "SERVER_PROTOCOL"=>"HTTP/1.1",
     "SERVER_SOFTWARE"=>"2.14.0",
     "GATEWAY_INTERFACE"=>"CGI/1.2",
     "REQUEST_METHOD"=>"GET",
     "REQUEST_PATH"=>"/xss",
     "REQUEST_URI"=>"/xss?a=b%28%29%22%26%251%27-%3B%3Csome_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88%2F%3E%27",
     "HTTP_VERSION"=>"HTTP/1.1",
     "HTTP_HOST"=>"127.0.0.2:4567",
     "HTTP_ACCEPT_ENCODING"=>"gzip, deflate",
     "HTTP_USER_AGENT"=>"Arachni/v2.0dev",
     "HTTP_ACCEPT"=>"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
     "HTTP_ACCEPT_LANGUAGE"=>"en-US,en;q=0.8,he;q=0.6",
     "HTTP_X_ARACHNI_SCAN_SEED"=>"7b092cea4f8784b9b52f0e7da0fbcb88",
     "HTTP_X_ARACHNI_ISSUE_REPLAY_ID"=>"f8fe8d0bd5305a1e4bceed94b3f68845",
     "HTTP_X_ARACHNI_ISSUE_SEED"=>"()\"&%1'-;<some_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88/>'",
     "HTTP_X_ARACHNI_ISSUE_DIGEST"=>"2593139878",
     "SERVER_NAME"=>"127.0.0.2",
     "SERVER_PORT"=>"4567",
     "PATH_INFO"=>"/xss",
     "REMOTE_ADDR"=>"127.0.0.1",
     "puma.socket"=>#<TCPSocket:(closed)>,
     "rack.hijack?"=>true,
     "rack.hijack"=>#<Puma::Client:0xf000dc @ready=false>,
     "rack.input"=>#<Puma::NullIO:0x000000024f6da0>,
     "rack.url_scheme"=>"http",
     "rack.after_reply"=>[],
     "sinatra.commonlogger"=>true,
     "rack.logger"=>
      #<Logger:0x00000001dff808
       @default_formatter=#<Logger::Formatter:0x00000001dff7b8 @datetime_format=nil>,
       @formatter=nil,
       @level=1,
       @logdev=#<Logger::LogDevice:0x00000001dff768 @dev=#<IO:<STDERR>>, @filename=nil, @mon_count=0, @mon_mutex=#<Thread::Mutex:0x00000001dff718>, @mon_owner=nil, @shift_age=nil, @shift_size=nil>,
       @progname=nil>,
     "rack.request.query_string"=>"a=b%28%29%22%26%251%27-%3B%3Csome_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88%2F%3E%27",
     "rack.request.query_hash"=>{"a"=>"b()\"&%1'-;<some_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88/>'"},
     "sinatra.route"=>"GET /xss"}

Now let's look at some cool stuff.

##### list_trace_points

    [2] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points
    ============================== Request #1 -- 2593139878
    0: [2016-04-19 21:51:56 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:51:56 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:51:56 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:51:56 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    => nil
    [3] pry(#<Arachni::Debug::Rack::Middleware>)>

Shows us trace points for the code that was executed when the web application served
the request that brought it to its vulnerable state.

This is a helper method, showing that type of information in a human readable format.

##### trace_points

    [3] pry(#<Arachni::Debug::Rack::Middleware>)> trace_points
    => {1=>
      [{:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:call, :binding=>#<Binding:0x00000001df0128>, :timestamp=>2016-04-19 21:51:56 +0300},
       {:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_call, :binding=>#<Binding:0x00000001deff20>, :timestamp=>2016-04-19 21:51:56 +0300},
       {:path=>"examples/server.rb", :line_number=>17, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:line, :binding=>#<Binding:0x00000001defd90>, :timestamp=>2016-04-19 21:51:56 +0300},
       {:path=>"examples/server.rb", :line_number=>18, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_return, :binding=>#<Binding:0x00000001def840>, :timestamp=>2016-04-19 21:51:56 +0300}]}
    [4] pry(#<Arachni::Debug::Rack::Middleware>)>

This is the actual data behind the `list_trace_points` output.

The most interesting bits are the `:bindings`, which allow us to get a glimpse
info the state of the web application at different stages while processing our request.

###### Stepping into bindings

    [4] pry(#<Arachni::Debug::Rack::Middleware>)> trace_points_for_request_id(1).first[:binding].pry

    From: /home/zapotek/workspace/arachni-debug-rack/examples/server.rb @ line 16 self.GET /xss:

        11:     <<EOHTML
        12:     <a href="/xss?a=b">XSS</a>
        13: EOHTML
        14: end
        15:
     => 16: get '/xss' do
        17:     params[:a]
        18: end

    [1] pry(#<Sinatra::Application>)>

We've now moved under the context of the web application, see:

    [1] pry(#<Sinatra::Application>)> __method__
    => :"GET /xss"
    [2] pry(#<Sinatra::Application>)> params
    => {"a"=>"b()\"&%1'-;<some_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88/>'"}
    [3] pry(#<Sinatra::Application>)> body
    => ["b()\"&%1'-;<some_dangerous_input_7b092cea4f8784b9b52f0e7da0fbcb88/>'"]

**A ha!**

The response body clearly includes the parameter value unescaped, which is why
the web application is vulnerable.

##### list_trace_points_for_request_id

This is a helper method, allowing us to filter trace points based on the request index,
in case we've run `arachni_reproduce` multiple times, for example:

    [1] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points
    ============================== Request #1 -- 2593139878
    0: [2016-04-19 21:51:56 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:51:56 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:51:56 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:51:56 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    ============================== Request #2 -- 2593139878
    0: [2016-04-19 21:54:39 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:54:39 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:54:39 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:54:39 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    ============================== Request #3 -- 2593139878
    0: [2016-04-19 21:54:41 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:54:41 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:54:41 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:54:41 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    [4] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points_for_request_id 1
    ============================== Request #1 -- 2593139878
    0: [2016-04-19 21:51:56 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:51:56 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:51:56 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:51:56 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    => nil

##### trace_points_for_request_id

    [2] pry(#<Arachni::Debug::Rack::Middleware>)> trace_points_for_request_id 1
    => [{:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:call, :binding=>#<Binding:0x00000001df0128>, :timestamp=>2016-04-19 21:51:56 +0300},
     {:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_call, :binding=>#<Binding:0x00000001deff20>, :timestamp=>2016-04-19 21:51:56 +0300},
     {:path=>"examples/server.rb", :line_number=>17, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:line, :binding=>#<Binding:0x00000001defd90>, :timestamp=>2016-04-19 21:51:56 +0300},
     {:path=>"examples/server.rb", :line_number=>18, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_return, :binding=>#<Binding:0x00000001def840>, :timestamp=>2016-04-19 21:51:56 +0300}]

Raw data behind `list_trace_points_for_request_id`.

##### list_trace_points_for_debug_id

This is a helper method, allowing us to filter trace points based on the value
of the `X-Arachni-Issue-Digest` request header, in case we're run `arachni_reproduce`
multiple times, for example:

    [6] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points
    ============================== Request #1 -- 2593139878
    0: [2016-04-19 21:51:56 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:51:56 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:51:56 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:51:56 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    ============================== Request #2 -- 2593139878
    0: [2016-04-19 21:54:39 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:54:39 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:54:39 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:54:39 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    ============================== Request #3 -- 2593139878
    0: [2016-04-19 21:54:41 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:54:41 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:54:41 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:54:41 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    => nil
    [8] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points_for_debug_id '2593139878'
    ============================== Request #1 -- 2593139878
    0: [2016-04-19 21:51:56 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:51:56 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:51:56 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:51:56 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    ============================== Request #2 -- 2593139878
    0: [2016-04-19 21:54:39 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:54:39 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:54:39 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:54:39 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    ============================== Request #3 -- 2593139878
    0: [2016-04-19 21:54:41 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-19 21:54:41 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-19 21:54:41 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-19 21:54:41 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    => nil

In this case we've only got one issue so we get all data.

##### trace_points_for_debug_id

    [9] pry(#<Arachni::Debug::Rack::Middleware>)> trace_points_for_debug_id '2593139878'
    => {1=>
      [{:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:call, :binding=>#<Binding:0x00000001df0128>, :timestamp=>2016-04-19 21:51:56 +0300},
       {:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_call, :binding=>#<Binding:0x00000001deff20>, :timestamp=>2016-04-19 21:51:56 +0300},
       {:path=>"examples/server.rb", :line_number=>17, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:line, :binding=>#<Binding:0x00000001defd90>, :timestamp=>2016-04-19 21:51:56 +0300},
       {:path=>"examples/server.rb", :line_number=>18, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_return, :binding=>#<Binding:0x00000001def840>, :timestamp=>2016-04-19 21:51:56 +0300}],
     2=>
      [{:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:call, :binding=>#<Binding:0x007f2ff002f748>, :timestamp=>2016-04-19 21:54:39 +0300},
       {:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_call, :binding=>#<Binding:0x007f2ff002f630>, :timestamp=>2016-04-19 21:54:39 +0300},
       {:path=>"examples/server.rb", :line_number=>17, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:line, :binding=>#<Binding:0x007f2ff002f518>, :timestamp=>2016-04-19 21:54:39 +0300},
       {:path=>"examples/server.rb", :line_number=>18, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_return, :binding=>#<Binding:0x007f2ff002f2c0>, :timestamp=>2016-04-19 21:54:39 +0300}],
     3=>
      [{:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:call, :binding=>#<Binding:0x007f3008062680>, :timestamp=>2016-04-19 21:54:41 +0300},
       {:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_call, :binding=>#<Binding:0x007f3008062568>, :timestamp=>2016-04-19 21:54:41 +0300},
       {:path=>"examples/server.rb", :line_number=>17, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:line, :binding=>#<Binding:0x007f3008062450>, :timestamp=>2016-04-19 21:54:41 +0300},
       {:path=>"examples/server.rb", :line_number=>18, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_return, :binding=>#<Binding:0x007f30080621f8>, :timestamp=>2016-04-19 21:54:41 +0300}]}

Raw data behind `list_trace_points_for_debug_id`.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/arachni/arachni-debug-rack.
