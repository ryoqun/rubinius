class Class
  def self.allocate
    Rubinius.primitive :class_s_allocate
    raise PrimitiveFailure, "Class.allocate primitive failed"
  end

  def set_superclass(sup)
    Rubinius.primitive :class_set_superclass
    kind = Rubinius::Type.object_class(sup)
    raise TypeError, "Class.set_superclass: argument must be a Class (#{kind} given)"
  end

  def class_id
    Rubinius.primitive :class_class_id
    raise PrimitiveFailure, "Class#class_id primitive failed"
  end

  def serial_id
    Rubinius.primitive :class_serial_id
    raise PrimitiveFailure, "Class#serial_id primitive failed"
  end

  private :set_superclass
end
