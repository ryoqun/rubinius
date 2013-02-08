# -*- encoding: us-ascii -*-

class Proc
  def to_s
    if @ruby_method
      code = @ruby_method.executable
      if code.respond_to? :file
        if code.lines
          line = code.first_line
        else
          line = "-1"
        end
        file = code.file
      else
        line = "-1"
        file = "(unknown)"
      end

      "#<#{self.class}:0x#{self.object_id.to_s(16)}@#{file}:#{line}>"
    else
      "#<#{self.class}:0x#{self.object_id.to_s(16)}@#{@block.file}:#{@block.line}>"
    end
  end

  alias_method :inspect, :to_s

  def self.__from_method__(meth)
    obj = __allocate__
    obj.ruby_method = meth

    return obj
  end

  def __yield__(*args, &block)
    # do a block style unwrap..
    if args.size == 1 and args.first.kind_of? Array and args.first.size > 1
      args = args.first
    end

    @ruby_method.call(*args, &block)
  end
end
