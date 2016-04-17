require 'rbconfig'

module Arachni
module Debug
module Rack
class Middleware

    HEADER_NAME      = 'HTTP_X_ARACHNI_DEBUG_ID'

    CALLBACK_LIBRARY = "#{File.expand_path( File.dirname(__FILE__) <<
                        '../../../../../' )}/callbacks/"
    CALLBACKS        = Dir.glob( "#{CALLBACK_LIBRARY}*.rb" ).
                        map { |f| File.basename( f, '.rb' ) }

    def initialize( app, options = {} )
        @app     = app
        @options = options

        @options[:callback] ||= {}

        fail ArgumentError, 'Missing callback.' if !@options[:callback][:name]

        # Maybe given a path to a script outside of the default location.
        external_callback = File.expand_path( @options[:callback][:name] )
        if File.exist?( external_callback )
            callback_location = external_callback
        else
            callback_location =
                "#{CALLBACK_LIBRARY}#{@options[:callback][:name]}.rb"

            if !File.exist?( callback_location )
                fail ArgumentError,
                     "Callback does not exist as '#{callback_location}' " <<
                         "nor '#{external_callback}'."
            end
        end

        @callback = IO.read( callback_location )
    end

    def call( env )
        code, headers, body = nil, nil, nil

        run_app = proc { code, headers, body = @app.call( env ) }

        if (debug_id = env[HEADER_NAME])
            run_and_trace( debug_id, &run_app )

            # Don't block the response
            Thread.new do
                begin
                    # These should be visible to the callback.
                    options = @options[:callback][:options] || {}

                    eval( @callback )
                rescue => e
                    log_exception( env['rack.logger'], e )
                end
            end

        else
            run_app.call
        end

        [ code, headers, body ]
    rescue => e
        log_exception( env['rack.logger'], e )
    end

    def list_trace_points_for_debug_id( debug_id )
        puts self.class.trace_points_to_string( trace_points_for_debug_id( debug_id ) )
    end

    def trace_points_for_debug_id( id )
        request_ids = self.class.debug_ids.select { |_, did| did == id }.keys
        trace_points.select { |request_id, _| request_ids.include? request_id }
    end

    def trace_points_for_request_id( id )
        trace_points[id]
    end

    def list_trace_points_for_request_id( id )
        puts self.class.trace_points_to_string( { id => trace_points_for_request_id( id ) } )
    end

    def trace_points
        self.class.trace_points
    end

    def list_trace_points
        puts self.class.trace_points_to_string( self.class.trace_points )
    end

    private

    def log_exception( logger, e )
        s = "[#{e.class}] #{e}: #{e.backtrace.first}"

        # STDERR.puts s
        logger.error s

        e.backtrace.each do |l|
            # STDERR.puts l
            logger.debug l
        end
    end

    def run_and_trace( debug_id, &block )
        self.class.increment_request_id
        request_id = self.class.request_id

        self.class.debug_ids[request_id]  = debug_id
        self.class.trace_points[request_id] ||= []

        TracePoint.new do |tp|
            if @options[:scope] &&
                !File.expand_path( tp.path ).start_with?( @options[:scope] )
                next
            end

            defined_class =
                (tp.defined_class.is_a?( Class ) || tp.defined_class.is_a?( Module ) ?
                    tp.defined_class.name : tp.defined_class.class.name)

            self.class.trace_points[request_id] << {
                path:        @options[:scope] ?
                                 tp.path.sub( @options[:scope],'' ): tp.path,
                line_number: tp.lineno,
                class_name:  defined_class,
                method_name: tp.method_id,
                event:       tp.event,
                binding:     tp.binding,
                timestamp:   Time.now
            }
        end.enable(&block)
    end

    class <<self
        
        def trace_points_to_string( trace_points )
            s = ''
            trace_points.each do |request_id, batch|
                s << "#{'=' * 30} Request ##{request_id} -- #{debug_ids[request_id]}\n"

                batch.each.with_index do |b, i|
                    s << "#{i}: [#{b[:timestamp]}] #{b[:path]}:" <<
                            "#{b[:line_number]} #{b[:class_name]}#" <<
                            "#{b[:method_name]} #{b[:event]} in " <<
                             "#{binding_to_string( b[:binding] )}\n"
                end
            end

            s
        end

        def binding_to_string( binding )
            s = "#{eval( 'self', binding ).class}"

            return s if !(container_method = eval( '__method__', binding ))

            s << "##{container_method}"

            mp, ml = eval( 'method(__method__).source_location', binding ) rescue nil || []
            return s if !ml

            s << "@#{mp}:#{ml}"
        end
        
        def debug_ids
            @debug_ids
        end

        def trace_points
            @trace_points
        end

        def request_id
            @request_id
        end

        # @private
        def increment_request_id
            @request_id += 1
        end

        def reset
            @debug_ids    = {}
            @trace_points = {}
            @request_id   = 0
        end

    end
    reset

end
end
end
end
