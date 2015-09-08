

class Qid
  def initialize path
    @path = path
    @inode = File.stat(path).ino
    @type = 0
  end

  def to_s
    [@type,0,@inode].pack("CVQ")
  end
end


#
# Implements the basics of the 9P2000.L
# protocol.
#
# It assumes an io-like object that implements
# blocking:
# 
#  * read(number of bytes)
#  * write(data)
#
# Note that this class will do small read/writes
# and it may be best to not hand it raw sockets
# but wrap it in a buffered implementation.
#
class Protocol9P2000L

  TGETATTR = 24
  RGETATTR = 26
  TVERSION = 100
  RVERSION = 101
  TATTACH = 104
  RATTACH = 105
  TCLUNK  = 120
  RCLUNK  = 121

  MessageMap = {
    TVERSION => [:tVersion, "WLS"],
    RVERSION => [:rVersion, "WLS"],
    TATTACH  => [:tAttach,"WLLSSL" ],
    RATTACH  => [:rAttach,"WI"],
    TGETATTR => [:tGetAttr,"WLQ"],
    RGETATTR => [:rGetAttr,"WQILLLQQQQQQQQQQQQQQ"],
    TCLUNK   => [:tClunk, "WL"],
    RCLUNK   => [:rClunk, "W"]
  }

  MAX_MSIZE = 65536
  VERSION_STRING = "9P2000.L"

  def initialize io
    @io = io

    # Msize gets set when client sents tVersion, so 
    # by default we set it to a reasonable maximum
    # for tVersion
    @msize = 200

    @fids = {}
  end


  def read_message
    data = @io.read(4)
    raise "FIXME: Disconnected?" if !data
    size = data.unpack("V").first
    if (size < 4 || size > @msize) 
      raise "Invalid packet size #{size}"
    end
    @io.read(size-4)
  end

  # B = byte
  # W = 16-bit little endian word
  # L = 32-bit little endian (long) word
  # S = String encoded as a 16-bit little endian length + a string of the number of bytes specified by length
  def unpack_message(format, message)
    pos = 1
    format.split("").collect do |f|
      r = nil
      case f
      when "B"
        r = message[pos].ord
        pos += 1
      when "W"
        r = message.unpack("@#{pos}v").first
        pos += 2
      when "L"
        r = message.unpack("@#{pos}V").first
        pos += 4
      when "Q"
        r = message.unpack("@#{pos}Q<").first
        pos += 8
      when "S"
        len = message.unpack("@#{pos}v").first
        pos += 2
        r = message[pos .. pos + len - 1]
        pos += len
      when "I"
        r = message.unpack("@#{pos}CVQ")
        pos += 13
      else
        raise "Invalid format specifier #{f}"
      end
      r
    end
  end

  def format_message(cmd,args,format)
    out = "xxxx"
    out << cmd.chr
    format.split("").zip(args) do |arg|
      f = arg[0]
      value = arg[1]
      case f
      when "B"
        out << value.chr
      when "W"
        out << [value].pack("v")
      when "L"
        out << [value].pack("V")
      when "Q"
        out << [value].pack("Q<")
      when "S"
        out << [value.length,value].pack("va*")
      when "I"
        out << value.to_s # Expected to be a Qid
      else
        raise "Invalid format specifier #{f}"
      end
    end
    out[0..3] = [out.size].pack("V")
    out
  end


  def print_message(cmdid, args)
    puts "DEBUG: #{cmdid.to_s}(#{args.collect(&:inspect).join(",")})"
  end

  def send_message(cmd, args)
    cmdrec = MessageMap[cmd]
    format = cmdrec[1]
    msg = format_message(cmd, args, format)
    unpacked = unpack_message(format, msg[4..-1])
    print_message(cmdrec[0], unpacked)
    p msg
    @io.write(msg)
  end

  

  # Process next inbound request
  def process_next
    message = read_message

    cmd = MessageMap[message[0].ord]

    if !cmd
      raise "Unknown / unsupported message #{message[0].ord}"
    end
    args = unpack_message(cmd[1],message)
    print_message(cmd[0],args)
    send(cmd[0], *args)
  end


  def tVersion(tag,msize,version)
    @msize = [MAX_MSIZE,msize].max
    rVersion(tag,@msize, VERSION_STRING == version ? version : "unknown")
    initSession
    true
  end

  def initSession
    # Terminate any pending IO
    # Clunk all fid's
    @fids = {}
  end

  def rVersion(tag,msize,version)
    send_message(RVERSION, [tag,msize,version])
  end

  def make_qid(name)
    Qid.new(name)
  end

  def tAttach(tag, fid, afid, uname, aname, n_uname)
    @fids[fid] = qid = make_qid(aname)
    rAttach(tag, qid)
  end

  def rAttach(tag,qid)
    send_message(RATTACH, [tag,qid])
  end

  def tGetAttr(tag, fid, request_mask)
    data = [0]*30
    rGetAttr(tag, 0, @fids[fid], *data)
  end

  def rGetAttr(tag, valid, qid, *data)
    send_message(RGETATTR, [tag,valid,qid].concat(data))
  end

  def tClunk(tag, fid)
    rClunk(tag)
  end

  def rClunk(tag)
    send_message(RCLUNK, [tag])
  end
end
