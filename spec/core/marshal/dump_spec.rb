require File.expand_path('../../../spec_helper', __FILE__)

describe "Marshal.dump" do
  it "dumps an AtomicReference" do
    atomic_reference = Rubinius::AtomicReference.new(0)
    Marshal.dump(atomic_reference).should == "\x04\bU:\x1ERubinius::AtomicReferencei\x00"
  end

  it "dumps a WeakRef" do
    atomic_reference = WeakRef.new(0)
    Marshal.dump(atomic_reference).should == "\x04\bU:\fWeakRefi\x00"
  end
end
