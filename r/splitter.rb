



class Splitter
  include Enumerable

  def initialize(pat=%r!^2007!, input=ARGF)
    @pat=pat
    @input=input
    @entry=''
    @first=true
    @finished=false
  end

  def one_entry
    while line = @input.gets
      begin
        if line =~ @pat
          if @first
            @entry=line
            @first=false
          else
            ret = @entry
            @entry = line
            return ret
          end
        else
          #@entry += line unless line =~ /^\r?$/
          @entry += line
        end
      rescue ArgumentError
        $stderr.print "ArgumentError: #{$!}\n"
        $stderr.print "Error line: #{line}\n"
        $stderr.print "Error line.encoding: #{line.encoding}\n"
        exit
      end
    end
    return nil if @finished
    @finished=true
    return @entry
  end

  def each
    while e=one_entry
      yield e
    end
  end
end
