# arachni-debug-rack

Allows debugging of issues idenified by [Arachni](http://www.arachni-scanner.com) in [Rack](https://github.com/rack/rack)-based web applications ([Rails](http://rubyonrails.org/), [Sinatra](http://sinatrarb.com/), etc.) by running user specified code upon issue reproduction.

The process goes something like this:

* Install `arachni-debug-rack` in web application.
* Run Arachni scan.
* Run `arachni_debug_rack_issue` with the scan report, `Issue#digest` and callback.
  * Replays issue.
  * Runs callback.
    * [IRB](https://en.wikipedia.org/wiki/Interactive_Ruby_Shell)
    * [Pry](https://github.com/pry/pry/)
    * [Better errors](https://github.com/charliesome/better_errors/) screen.
    * Arbitrary code.
  * **DEBUG**: The callback would run under the vulnerable state of web application, thus allowing for the issue to be debugged; the triggering of the issue would in essence be the breakpoint.
