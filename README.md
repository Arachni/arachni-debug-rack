# arachni-debug-rack

Allows debugging of vulnerabilities identified by [Arachni](http://www.arachni-scanner.com)
in [Rack](https://github.com/rack/rack)-based web applications ([Rails](http://rubyonrails.org/),
[Sinatra](http://sinatrarb.com/), etc.) by running user specified code upon issue reproduction.

The process goes something like this:

* Install `arachni-debug-rack` in web application.
  * Set desired callback.
* Run Arachni scan.
* Run `arachni_debug_rack_issue` with the scan report and `Issue#digest`.
  * Replays issue.
  * Runs callback.
    * [IRB](https://en.wikipedia.org/wiki/Interactive_Ruby_Shell)
    * [Pry](https://github.com/pry/pry/)
      * [Remote](https://github.com/Mon-Ouie/pry-remote) as well.
    * [Better errors](https://github.com/charliesome/better_errors/) -- pending.
    * External Ruby scripts.
  * **DEBUG**: The callback runs under the vulnerable state of web application,
    thus allowing for the issue to be debugged.

**Still in alpha phase, may break compatibility (or altogether) without warning).**

## Installation

Add the following to your `Gemfile`:

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
[example Sinatra application](https://github.com/arachni/arachni-debug-rack/master/examples/server.rb):

    # We could just use IRB for these example, but 'pry' will really drive this home.
    gem install pry
    bundle exec ruby examples/server.rb -o 0.0.0.0

### Step 1

Download one of the [Arachni packages](http://www.arachni-scanner.com/download/)
and configure your `$PATH` env variable to include its `bin/` directory:

    export PATH=$PATH:/path/to/arachni/bin

You can verify with:

    arachni --version

If you see the following it means that you probably made a typo when specifying
the path:

    arachni: command not found

Otherwise you'll see Arachni's version information.

**Please make sure that this is the only instance of Arachni on your system.**

### Step 2

Scan the web application using [Arachni](http://www.arachni-scanner.com) and get
your hands on the resulting AFR report, for example:

    ./bin/arachni http://127.0.0.2:4567/ --checks xss --browser-cluster-pool-size=0 --report-save-path=report.afr

### Step 3

Copy the `Digest` of the issue you'd like to debug, which you can find towards the
top of each issue printout:

    [+] [1] Cross-Site Scripting (XSS) (Trusted)
    [~] ~~~~~~~~~~~~~~~~~~~~
    [~] Digest:     2593139878
    [~] Severity:   High

In this case we only have one issue, with a digest of `2593139878`.

_This information is included in all report formats._

### Step 4

Pass the report and the issue digest to `arachni_debug_rack_issue` like so:

    ./bin/arachni_debug_rack_issue report.afr 2593139878

This will actually be executed by the `arachni_script` executable, which is
provided by the [Arachni](http://www.arachni-scanner.com/download/) packages.

If you get the following error please ensure "Step 1" was successful:

    /usr/bin/env: arachni_script: No such file or directory

If everything went OK, you'll see something like:

    ================================================== Cross-Site Scripting (XSS) in link input "a" ==================================================
                                   Using "b<some_dangerous_input_911d4dc4346498b0467e5998d887e101/>"
                                   At http://127.0.0.2:4567/xss?a=b%3Csome_dangerous_input_911d4dc4346498b0467e5998d887e101/%3E

    Client-side scripts are used extensively by modern web applications.
    They perform from simple functions (such as the formatting of text) up to full
    manipulation of client-side data and Operating System interaction.

    Cross Site Scripting (XSS) allows clients to inject scripts into a request and
    have the server return the script to the client in the response. This occurs
    because the application is taking untrusted data (in this example, from the client)
    and reusing it without performing any validation or sanitisation.

    If the injected script is returned immediately this is known as reflected XSS.
    If the injected script is stored by the server and returned to any client visiting
    the affected page, then this is known as persistent XSS (also stored XSS).

    Arachni has discovered that it is possible to insert script content directly into
    HTML element content.

    Digest:     2593139878
    Severity:   High
    Tags:       xss, regexp, injection, script

    CWE: http://cwe.mitre.org/data/definitions/79.html

    References:
      Secunia - http://secunia.com/advisories/9716/
      WASC - http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting
      OWASP - https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet

    URL:        http://127.0.0.2:4567/xss
    Element:    link
    All inputs: a
    Method:     GET
    Input name: a

    Seed:      "<some_dangerous_input_911d4dc4346498b0467e5998d887e101/>"
    Injected:  "b<some_dangerous_input_911d4dc4346498b0467e5998d887e101/>"
    Proof:     "<some_dangerous_input_911d4dc4346498b0467e5998d887e101/>"

    Referring page: http://127.0.0.2:4567/

    Affected page:  http://127.0.0.2:4567/xss?a=b%3Csome_dangerous_input_911d4dc4346498b0467e5998d887e101/%3E
    HTTP request
    GET /xss?a=b%3Csome_dangerous_input_911d4dc4346498b0467e5998d887e101%2F%3E HTTP/1.1
    Host: 127.0.0.2:4567
    Accept-Encoding: gzip, deflate
    User-Agent: Arachni/v2.0dev
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.8,he;q=0.6

    -------------------------------------------------- Reproducing --------------------------------------------------

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
     [*] XSS: Analyzing response #4 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [+] XSS: In link input 'a' with action http://127.0.0.2:4567/xss
     [*] XSS: Analyzing response #0 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [+] XSS: In link input 'a' with action http://127.0.0.2:4567/xss
     [*] XSS: Analyzing response #1 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [*] XSS: Analyzing response #2 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [+] XSS: In link input 'a' with action http://127.0.0.2:4567/xss
     [*] XSS: Analyzing response #3 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'
     [*] XSS: Analyzing response #5 for link input 'a' pointing to: 'http://127.0.0.2:4567/xss'

    -------------------------------------------------- Seed --------------------------------------------------

    </textarea>--><some_dangerous_input_6ae17bb24cafdd040964c697afe2faeb/><!--<textarea>

    You can use the above to identify tainted inputs (params, cookies, etc.) and sinks (response bodies, SQL queries etc.).
    It is accessible via the 'X-Arachni-Debug-Id' header: env['HTTP_X_ARACHNI_DEBUG_ID']

    -------------------------------------------------- Request --------------------------------------------------

    GET /xss?a=b%3C%2Ftextarea%3E--%3E%3Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%2F%3E%3C%21--%3Ctextarea%3E HTTP/1.1
    Host: 127.0.0.2:4567
    Accept-Encoding: gzip, deflate
    User-Agent: Arachni/v2.0dev
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.8,he;q=0.6
    X-Arachni-Debug-Id: </textarea>--><some_dangerous_input_6ae17bb24cafdd040964c697afe2faeb/><!--<textarea>


    -------------------------------------------------- Response --------------------------------------------------

    HTTP/1.1 200 OK
    Content-Type: text/html;charset=utf-8
    X-XSS-Protection: 1; mode=block
    X-Content-Type-Options: nosniff
    X-Frame-Options: SAMEORIGIN
    Content-Length: 85

    b</textarea>--><some_dangerous_input_6ae17bb24cafdd040964c697afe2faeb/><!--<textarea>

### Step 5

**Tada!**

If you step over to the terminal of your web application, you'll see a Pry prompt
waiting for you, something like:

    127.0.0.1 - - [16/Apr/2016:22:35:13 +0300] "GET /xss?a=b%3C%2Ftextarea%3E--%3E%3Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%2F%3E%3C%21--%3Ctextarea%3E HTTP/1.1" 200 85 0.0020
    127.0.0.1 - - [16/Apr/2016:22:35:13 +0300] "GET /xss?a=b%253C%252Ftextarea%253E--%253E%253Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%252F%253E%253C%2521--%253Ctextarea%253E HTTP/1.1" 200 107 0.0003
    127.0.0.1 - - [16/Apr/2016:22:35:13 +0300] "GET /xss?a=b%3Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%2F%3E HTTP/1.1" 200 57 0.0041
    127.0.0.1 - - [16/Apr/2016:22:35:13 +0300] "GET /xss?a=b%2528%2529%2522%2526%25251%2527-%253B%253Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%252F%253E%2527 HTTP/1.1" 200 89 0.0030
    127.0.0.1 - - [16/Apr/2016:22:35:13 +0300] "GET /xss?a=b%253Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%252F%253E HTTP/1.1" 200 63 0.0061
    127.0.0.1 - - [16/Apr/2016:22:35:13 +0300] "GET /xss?a=b%28%29%22%26%251%27-%3B%3Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%2F%3E%27 HTTP/1.1" 200 67 0.0052
    127.0.0.1 - - [16/Apr/2016:22:35:13 +0300] "GET /xss?a=b%3C%2Ftextarea%3E--%3E%3Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%2F%3E%3C%21--%3Ctextarea%3E HTTP/1.1" 200 85 0.0071
    [1] pry(#<Arachni::Debug::Rack::Middleware>)>

We're now operating under the context of the middleware, see:

    [1] pry(#<Arachni::Debug::Rack::Middleware>)> env
    => {"rack.version"=>[1, 3],
     "rack.errors"=>#<IO:<STDERR>>,
     "rack.multithread"=>true,
     "rack.multiprocess"=>false,
     "rack.run_once"=>false,
     "SCRIPT_NAME"=>"",
     "QUERY_STRING"=>"a=b%3C%2Ftextarea%3E--%3E%3Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%2F%3E%3C%21--%3Ctextarea%3E",
     "SERVER_PROTOCOL"=>"HTTP/1.1",
     "SERVER_SOFTWARE"=>"2.14.0",
     "GATEWAY_INTERFACE"=>"CGI/1.2",
     "REQUEST_METHOD"=>"GET",
     "REQUEST_PATH"=>"/xss",
     "REQUEST_URI"=>"/xss?a=b%3C%2Ftextarea%3E--%3E%3Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%2F%3E%3C%21--%3Ctextarea%3E",
     "HTTP_VERSION"=>"HTTP/1.1",
     "HTTP_HOST"=>"127.0.0.2:4567",
     "HTTP_ACCEPT_ENCODING"=>"gzip, deflate",
     "HTTP_USER_AGENT"=>"Arachni/v2.0dev",
     "HTTP_ACCEPT"=>"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
     "HTTP_ACCEPT_LANGUAGE"=>"en-US,en;q=0.8,he;q=0.6",
     "HTTP_X_ARACHNI_DEBUG_ID"=>"</textarea>--><some_dangerous_input_6ae17bb24cafdd040964c697afe2faeb/><!--<textarea>",
     "SERVER_NAME"=>"127.0.0.2",
     "SERVER_PORT"=>"4567",
     "PATH_INFO"=>"/xss",
     "REMOTE_ADDR"=>"127.0.0.1",
     "puma.socket"=>#<TCPSocket:(closed)>,
     "rack.hijack?"=>true,
     "rack.hijack"=>#<Puma::Client:0x150b558 @ready=false>,
     "rack.input"=>#<Puma::NullIO:0x000000030701e0>,
     "rack.url_scheme"=>"http",
     "rack.after_reply"=>[],
     "sinatra.commonlogger"=>true,
     "rack.logger"=>
      #<Logger:0x00000002a15b60
       @default_formatter=#<Logger::Formatter:0x00000002a15a48 @datetime_format=nil>,
       @formatter=nil,
       @level=1,
       @logdev=#<Logger::LogDevice:0x00000002a159d0 @dev=#<IO:<STDERR>>, @filename=nil, @mon_count=0, @mon_mutex=#<Thread::Mutex:0x00000002a158b8>, @mon_owner=nil, @shift_age=nil, @shift_size=nil>,
       @progname=nil>,
     "rack.request.query_string"=>"a=b%3C%2Ftextarea%3E--%3E%3Csome_dangerous_input_6ae17bb24cafdd040964c697afe2faeb%2F%3E%3C%21--%3Ctextarea%3E",
     "rack.request.query_hash"=>{"a"=>"b</textarea>--><some_dangerous_input_6ae17bb24cafdd040964c697afe2faeb/><!--<textarea>"},
     "sinatra.route"=>"GET /xss"}
    [2] pry(#<Arachni::Debug::Rack::Middleware>)>

Now let's look at some cool stuff.

#### list_trace_points

    [2] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points
    ============================== Request #1 -- </textarea>--><some_dangerous_input_6ae17bb24cafdd040964c697afe2faeb/><!--<textarea>
    0: [2016-04-16 22:35:13 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-16 22:35:13 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-16 22:35:13 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-16 22:35:13 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    => nil
    [3] pry(#<Arachni::Debug::Rack::Middleware>)>

Shows us trace points for the code that was executed when the web application served
the request that brought it to its vulnerable state.

This is a helper method, showing that type of information in a human readable format.

#### trace_points

    [3] pry(#<Arachni::Debug::Rack::Middleware>)> trace_points
    => {1=>
      [{:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:call, :binding=>#<Binding:0x000000029daf10>, :timestamp=>2016-04-16 22:35:13 +0300},
       {:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_call, :binding=>#<Binding:0x000000029dad30>, :timestamp=>2016-04-16 22:35:13 +0300},
       {:path=>"examples/server.rb", :line_number=>17, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:line, :binding=>#<Binding:0x000000029dabc8>, :timestamp=>2016-04-16 22:35:13 +0300},
       {:path=>"examples/server.rb", :line_number=>18, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_return, :binding=>#<Binding:0x000000029da8a8>, :timestamp=>2016-04-16 22:35:13 +0300}]}
    [4] pry(#<Arachni::Debug::Rack::Middleware>)>

This is the actual data behind the `list_trace_points` output.

The most interesting bits are the `:bindings`, which allow us to get a glimpse
info the state of the web application at different stages while processing out request.

##### Stepping into bindings

    [4] pry(#<Arachni::Debug::Rack::Middleware>)> trace_points.values.first.first[:binding].pry

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
    => {"a"=>"b</textarea>--><some_dangerous_input_6ae17bb24cafdd040964c697afe2faeb/><!--<textarea>"}
    [3] pry(#<Sinatra::Application>)> body
    => ["b</textarea>--><some_dangerous_input_6ae17bb24cafdd040964c697afe2faeb/><!--<textarea>"]

**A ha!**

The response body clearly includes the parameter value unescaped, which is why
the web application is vulnerable.

#### list_trace_points_for_request_id

This is a helper method, allowing us to filter trace points based on the request index,
in case we're run `arachni_debug_rack_issue` multiple times, for example:

    [1] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points
    ============================== Request #1 -- <some_dangerous_input_341bd0d9d8094eab4c3edbf3dfe708c5/>
    0: [2016-04-16 22:44:50 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-16 22:44:50 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-16 22:44:50 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-16 22:44:50 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    ============================== Request #2 -- <some_dangerous_input_0f4f52bc8fb862287fe86fb6532766d4/>
    0: [2016-04-16 22:44:52 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-16 22:44:52 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-16 22:44:52 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-16 22:44:52 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    [2] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points_for_request_id 1
    ============================== Request #1 -- <some_dangerous_input_341bd0d9d8094eab4c3edbf3dfe708c5/>
    0: [2016-04-16 22:44:50 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-16 22:44:50 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-16 22:44:50 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-16 22:44:50 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    => nil

#### trace_points_for_request_id

    [3] pry(#<Arachni::Debug::Rack::Middleware>)> trace_points_for_request_id 1
    => [{:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:call, :binding=>#<Binding:0x000000029f2430>, :timestamp=>2016-04-16 22:44:50 +0300},
     {:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_call, :binding=>#<Binding:0x000000029f2138>, :timestamp=>2016-04-16 22:44:50 +0300},
     {:path=>"examples/server.rb", :line_number=>17, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:line, :binding=>#<Binding:0x000000029f1e68>, :timestamp=>2016-04-16 22:44:50 +0300},
     {:path=>"examples/server.rb", :line_number=>18, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_return, :binding=>#<Binding:0x000000029f1b20>, :timestamp=>2016-04-16 22:44:50 +0300}]

Raw data behind `list_trace_points_for_request_id`.

#### list_trace_points_for_debug_id

This is a helper method, allowing us to filter trace points based on the value
of the `X-Arachni-Debug-Id` request header, in case we're run `arachni_debug_rack_issue`
multiple times, for example:

    [5] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points
    ============================== Request #1 -- <some_dangerous_input_341bd0d9d8094eab4c3edbf3dfe708c5/>
    0: [2016-04-16 22:44:50 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-16 22:44:50 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-16 22:44:50 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-16 22:44:50 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    ============================== Request #2 -- <some_dangerous_input_0f4f52bc8fb862287fe86fb6532766d4/>
    0: [2016-04-16 22:44:52 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-16 22:44:52 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-16 22:44:52 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-16 22:44:52 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss
    => nil
    [6] pry(#<Arachni::Debug::Rack::Middleware>)> list_trace_points_for_debug_id '<some_dangerous_input_0f4f52bc8fb862287fe86fb6532766d4/>'
    ============================== Request #2 -- <some_dangerous_input_0f4f52bc8fb862287fe86fb6532766d4/>
    0: [2016-04-16 22:44:52 +0300] examples/server.rb:16 Sinatra::Application#GET /xss call in Sinatra::Application#GET /xss
    1: [2016-04-16 22:44:52 +0300] examples/server.rb:16 Sinatra::Application#GET /xss b_call in Sinatra::Application#GET /xss
    2: [2016-04-16 22:44:52 +0300] examples/server.rb:17 Sinatra::Application#GET /xss line in Sinatra::Application#GET /xss
    3: [2016-04-16 22:44:52 +0300] examples/server.rb:18 Sinatra::Application#GET /xss b_return in Sinatra::Application#GET /xss

#### trace_points_for_debug_id

[12] pry(#<Arachni::Debug::Rack::Middleware>)> trace_points_for_debug_id '<some_dangerous_input_0f4f52bc8fb862287fe86fb6532766d4/>'
=> {2=>
  [{:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:call, :binding=>#<Binding:0x007f05ec04b980>, :timestamp=>2016-04-16 22:44:52 +0300},
   {:path=>"examples/server.rb", :line_number=>16, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_call, :binding=>#<Binding:0x007f05ec04b868>, :timestamp=>2016-04-16 22:44:52 +0300},
   {:path=>"examples/server.rb", :line_number=>17, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:line, :binding=>#<Binding:0x007f05ec04b750>, :timestamp=>2016-04-16 22:44:52 +0300},
   {:path=>"examples/server.rb", :line_number=>18, :class_name=>"Sinatra::Application", :method_name=>:"GET /xss", :event=>:b_return, :binding=>#<Binding:0x007f05ec04b4f8>, :timestamp=>2016-04-16 22:44:52 +0300}]}

Raw data behind `list_trace_points_for_debug_id`.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/arachni/arachni-debug-rack.
