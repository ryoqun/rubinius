module Rubinius
  class CallSite

    attr_reader :name
    attr_reader :executable

    def hits
      0
    end

    def ip
      Rubinius.primitive :call_site_ip
      raise PrimitiveFailure, "CallSite#ip primitive failed"
    end

    def update_call_site(other)
      Rubinius.primitive :call_site_update_call_site
      raise PrimitiveFailure, "CallSite#update_call_site primitive failed"
    end

    def location
      "#{@executable.file}:#{@executable.line_from_ip(ip)}"
    end

    def inspect
      "#<#{self.class.name}:0x#{self.object_id.to_s(16)} #{location}##{@name}(#{hits})>"
    end

  end

  class OptimizedCallSite < CallSite
    attr_reader :fallback_call_site
    attr_accessor :optimized_code

    def self.new(call_sitek, original_code)
      Rubinius.primitive :optimized_call_site_allocate
      raise PrimitiveFailure, "OptimizedCallSite.allocate primitive failed"
    end

    def inject
      fallback_call_site.update_call_site(self)
    end

    def eject
      update_call_site(fallback_call_site)
    end

    def inspect
      "#<#{self.class.name}:0x#{self.object_id.to_s(16)} fallback:#{fallback_call_site.inspect}>"
    end
  end

  class Guard
    attr_accessor :reference

    def self.new(reference, object)
      Rubinius.primitive :guard_allocate
      raise PrimitiveFailure, "Guard.allocate primitive failed"
    end

    def class_data
      Rubinius.primitive :guard_class_data
      raise PrimitiveFailure, "Guard.class_data primitive failed"
    end

    def inspect
      data = class_data
      "#<#{self.class.name}:0x#{self.object_id.to_s(16)} reference:#{reference.inspect} class_id:#{data[0]} serial_id:#{data[1]}>"
    end
  end
end
