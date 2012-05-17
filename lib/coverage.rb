module Coverage
  class << self
    def start(*args)
    end

    def result
      Hash[Rubinius.coverage.to_a.collect{|f,c| c.shift; [f.to_s, c]}]
    end
  end
end
