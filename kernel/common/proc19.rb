# -*- encoding: us-ascii -*-

class Proc

  alias_method :===, :call
  alias_method :eql?, :==

  def curry(curried_arity = nil)
    if lambda? && curried_arity
      if arity > 0 && curried_arity != arity
        raise ArgumentError, "Wrong number of arguments (%i for %i)" % [
          curried_arity,
          arity
        ]
      end

      if arity < 0 && curried_arity < (-arity - 1)
        raise ArgumentError, "Wrong number of arguments (%i for %i)" % [
          curried_arity,
          -arity - 1
        ]
      end
    end

    args = []

    my_self = self
    m = lambda? ? :lambda : :proc
    f = __send__(m) {|*x|
      call_args = args + x
      if call_args.length >= my_self.arity
        my_self[*call_args]
      else
        args = call_args
        f
      end
    }

    f.singleton_class.send(:define_method, :binding) {
      raise ArgumentError, "cannot create binding from f proc"
    }

    f.singleton_class.send(:define_method, :parameters) {
      [[:rest]]
    }

    f.singleton_class.send(:define_method, :source_location) {
      nil
    }

    f
  end

  def source_location
    if @bound_method
      if @bound_method.respond_to?(:source_location)
        return @bound_method.source_location
      else
        return nil
      end
    end

    [@block.file.to_s, @block.line]
  end

  def to_s
    file, line = source_location

    l = " (lambda)" if lambda?
    if file and line
      "#<#{self.class}:0x#{self.object_id.to_s(16)}@#{@block.file}:#{@block.line}#{l}>"
    else
      "#<#{self.class}:0x#{self.object_id.to_s(16)}#{l}>"
    end
  end

  alias_method :inspect, :to_s

  class Method < Proc
    def self.__from_method__(meth)
      obj = __allocate__
      obj.bound_method = meth
      obj.lambda_style!

      return obj
    end

    def source_location
      code = @bound_method.executable
      if code.respond_to? :file
        if code.lines
          line = code.first_line
        else
          line = -1
        end
        file = code.file
      else
        line = -1
        file = "(unknown)"
      end

      [file.to_s, line]
    end

    def __yield__(*args, &block)
      @bound_method.call(*args, &block)
    end
  end

end
