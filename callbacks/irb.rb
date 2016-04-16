require 'irb'

ARGV.clear

module ::IRB
    def self.start_session( binding )
        ::IRB.setup( nil )

        workspace = ::IRB::WorkSpace.new( binding )

        if ::IRB.conf[:SCRIPT]
            irb = Irb.new( workspace, ::IRB.conf[:SCRIPT] )
        else
            irb = Irb.new( workspace )
        end

        ::IRB.conf[:IRB_RC].call( irb.context ) if ::IRB.conf[:IRB_RC]
        ::IRB.conf[:MAIN_CONTEXT] = irb.context

        trap( 'SIGINT' ) do
            irb.signal_handle
        end

        catch( :IRB_EXIT ) do
            irb.eval_input
        end
    end
end

::IRB.start_session( binding )
