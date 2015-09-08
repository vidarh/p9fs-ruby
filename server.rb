
require 'socket'

require_relative 'protocol'


srv = TCPServer.open(1942)

while client = srv.accept

  proto = Protocol9P2000L.new(client)

  while proto.process_next
  end
end
