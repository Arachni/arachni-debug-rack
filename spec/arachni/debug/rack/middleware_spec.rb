require 'spec_helper'

describe Arachni::Debug::Rack::Middleware do
    include Rack::Test::Methods

    before do
        $spec_callback    = nil
        $callback_options = nil
        $callback_ran     = nil

        described_class.reset
    end

    def send_trace_request( debug_id = '1', params = {} )
        get '/', params, { described_class::HEADER_NAME => debug_id }
    end

    def wait_for_callback
        sleep 0.1 while !$callback_ran
        $callback_ran = nil
    end

    let(:app) { MockApp }
    let(:trace_points) { described_class.trace_points }

    describe '#initialize' do
        describe ':callbacks' do
            describe ':name' do
                context 'when internal' do
                    described_class::CALLBACKS.each do |name|
                        context name do
                            it 'loads it' do
                                expect(IO).to receive(:read).with( "#{described_class::CALLBACK_LIBRARY}#{name}.rb" )
                                described_class.new( app, callback: { name: name } )
                            end
                        end
                    end
                end

                context 'when external' do
                    it 'loads it' do
                        expect(IO).to receive(:read).with( __FILE__ )
                        described_class.new( app, callback: { name: __FILE__ } )
                    end
                end

                context 'when non existent' do
                    it 'raises ArgumentError' do
                        expect do
                            described_class.new( app, callback: { name: 'blah' } )
                        end.to raise_error ArgumentError
                    end
                end

                context 'when missing' do
                    it 'raises ArgumentError' do
                        expect do
                            described_class.new( app, callback: { } )
                        end.to raise_error ArgumentError
                    end
                end
            end

            context 'when missing' do
                it 'raises ArgumentError' do
                    expect do
                        described_class.new( app )
                    end.to raise_error ArgumentError
                end
            end
        end
    end

    describe '#call' do
        context "when the #{described_class::HEADER_NAME} header is not set" do
            it 'does not trace the code' do
                expect(trace_points).to be_empty
                get '/', { 'a' => 'b' }
                expect(trace_points).to be_empty
            end
        end

        context "when the #{described_class::HEADER_NAME} header is set" do
            it 'traces the code' do
                expect(trace_points).to be_empty

                send_trace_request( '1', { 'a' => 'b' } )
                send_trace_request( '2', { 'c' => 'd' } )

                expect(trace_points).to be_any

                expect(described_class.trace_points[1].first[:binding].eval('params')).to eq({'a' => 'b'})
                expect(described_class.trace_points[2].first[:binding].eval('params')).to eq({'c' => 'd'})

                trace_points.each do |_, batch|
                    batch.each do |tp|
                        expect(tp[:timestamp]).to be_kind_of Time
                        tp.delete :timestamp

                        expect(tp[:binding]).to be_kind_of Binding
                        tp.delete :binding
                    end
                end

                expect(trace_points).to eq({
                    1 =>
                        [
                            { :path        => "/mock_app.rb",
                              :line_number => 16,
                              :class_name  => "MockApp",
                              :method_name => :"GET /",
                              :event       => :call
                            },
                            { :path        => "/mock_app.rb",
                              :line_number => 16,
                              :class_name  => "MockApp",
                              :method_name => :"GET /",
                              :event       => :b_call
                            },
                            { :path        => "/mock_app.rb",
                              :line_number => 17,
                              :class_name  => "MockApp",
                              :method_name => :"GET /",
                              :event       => :line
                            },
                            { :path        => "/mock_app.rb",
                              :line_number => 20,
                              :class_name  => "MockApp",
                              :method_name => :"GET /",
                              :event       => :b_return
                            }
                        ],
                    2 =>
                        [
                            { :path        => "/mock_app.rb",
                              :line_number => 16,
                              :class_name  => "MockApp",
                              :method_name => :"GET /",
                              :event       => :call
                            },
                            { :path        => "/mock_app.rb",
                              :line_number => 16,
                              :class_name  => "MockApp",
                              :method_name => :"GET /",
                              :event       => :b_call
                            },
                            { :path        => "/mock_app.rb",
                              :line_number => 17,
                              :class_name  => "MockApp",
                              :method_name => :"GET /",
                              :event       => :line
                            },
                            { :path        => "/mock_app.rb",
                              :line_number => 20,
                              :class_name  => "MockApp",
                              :method_name => :"GET /",
                              :event       => :b_return
                            }
                        ]
                })
            end

            it 'increments the request id' do
                expect(described_class.request_id).to eq 0

                send_trace_request

                expect(described_class.request_id).to eq 1
            end

            it 'updates the request-ID/debug-Id association' do
                expect(described_class.debug_ids).to be_empty

                send_trace_request( '2' )

                expect(described_class.debug_ids[1]).to eq '2'
            end

            it 'runs the callback and forwards callback options' do
                send_trace_request

                wait_for_callback

                expect($callback_options).to eq( blah: 'stuff' )
            end
        end
    end

    describe '#list_trace_points' do
        let(:timestamp) { Time.now }
        let(:tps) do
            s =
"============================== Request #1 -- 1
0: [#{timestamp}] /mock_app.rb:16 MockApp#GET / call in MockApp#GET /
1: [#{timestamp}] /mock_app.rb:16 MockApp#GET / b_call in MockApp#GET /
2: [#{timestamp}] /mock_app.rb:17 MockApp#GET / line in MockApp#GET /
3: [#{timestamp}] /mock_app.rb:20 MockApp#GET / b_return in MockApp#GET /
"

        end

        it 'lists all trace points' do
            trace_points.each do |_, batch|
                batch.each do |tp|
                    tp[:timestamp] = timestamp
                end
            end

            expect(STDOUT).to receive(:puts).with(tps)

            $spec_callback = proc { list_trace_points }

            send_trace_request
            wait_for_callback
        end
    end

    describe '#list_trace_points_for_request_id' do
        let(:timestamp) { Time.now }
        let(:tps) do
            s =
                "============================== Request #2 -- 2
0: [#{timestamp}] /mock_app.rb:16 MockApp#GET / call in MockApp#GET /
1: [#{timestamp}] /mock_app.rb:16 MockApp#GET / b_call in MockApp#GET /
2: [#{timestamp}] /mock_app.rb:17 MockApp#GET / line in MockApp#GET /
3: [#{timestamp}] /mock_app.rb:20 MockApp#GET / b_return in MockApp#GET /
"

        end

        it 'lists all trace points for the given request ID' do
            trace_points.each do |_, batch|
                batch.each do |tp|
                    tp[:timestamp] = timestamp
                end
            end

            send_trace_request( '1' )
            wait_for_callback

            send_trace_request( '2' )
            wait_for_callback

            expect(STDOUT).to receive(:puts).with(tps)
            $spec_callback = proc { list_trace_points_for_request_id( 2 ) }

            send_trace_request( '3' )
            wait_for_callback
        end
    end

    describe '#trace_points_for_request_id' do
        it 'returns trace points for the given request ID' do
            send_trace_request
            wait_for_callback

            send_trace_request
            wait_for_callback

            tps = nil
            $spec_callback = proc { tps = trace_points_for_request_id( 2 ) }

            send_trace_request
            wait_for_callback

            expect(tps).to eq trace_points[2]
        end
    end

    describe '#list_trace_points_for_debug_id' do
        let(:timestamp) { Time.now }
        let(:tps) do
            s =
                "============================== Request #2 -- 1
0: [#{timestamp}] /mock_app.rb:16 MockApp#GET / call in MockApp#GET /
1: [#{timestamp}] /mock_app.rb:16 MockApp#GET / b_call in MockApp#GET /
2: [#{timestamp}] /mock_app.rb:17 MockApp#GET / line in MockApp#GET /
3: [#{timestamp}] /mock_app.rb:20 MockApp#GET / b_return in MockApp#GET /
"

        end

        it 'lists all trace points for the given request ID' do
            trace_points.each do |_, batch|
                batch.each do |tp|
                    tp[:timestamp] = timestamp
                end
            end

            send_trace_request( '2' )
            wait_for_callback

            send_trace_request( '1' )
            wait_for_callback

            expect(STDOUT).to receive(:puts).with(tps)
            $spec_callback = proc { list_trace_points_for_debug_id( '1' ) }

            send_trace_request( '3' )
            wait_for_callback
        end
    end

    describe '#trace_points_for_debug_id' do
        it 'returns trace points for the given request ID' do
            send_trace_request( '2' )
            wait_for_callback

            send_trace_request( '1' )
            wait_for_callback

            tps = nil
            $spec_callback = proc { tps = trace_points_for_debug_id( '1' ) }

            send_trace_request( '3' )
            wait_for_callback

            expect(tps).to eq({ 2 => trace_points[2] })
        end
    end
end
