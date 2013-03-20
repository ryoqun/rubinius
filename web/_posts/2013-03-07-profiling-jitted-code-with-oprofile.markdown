---
layout: post
title: Profiling JIT-ted Ruby code with OProfile
author: Ryo Onodera
---

You can now profile JIT-ted Ruby code!

Before:

    samples  %        app name                 symbol name
    488      26.1522  rbx                      rubinius::MachineCode::interpreter(rubinius::State*, rubinius::MachineCode*, rubinius::InterpreterCallFrame*)
    386      20.6860  anon (tgid:7826 range:0xb577f000-0xb57ff000) anon (tgid:7826 range:0xb577f000-0xb57ff000)
      # => The dark world of JIT-ted Ruby code
    132       7.0740  rbx                      rbx_set_local_depth
    122       6.5380  rbx                      __x86.get_pc_thunk.bx
    109       5.8414  rbx                      rubinius::BlockEnvironment::call(rubinius::State*, rubinius::CallFrame*, rubinius::Arguments&, int)
    81        4.3408  rbx                      rbx_push_local_depth
    80        4.2872  no-vmlinux               /no-vmlinux
    52        2.7867  rbx                      rubinius::VariableScope::set_local(int, rubinius::Object*)
    50        2.6795  rbx                      bool rubinius::kind_of<rubinius::Fiber>(rubinius::Object const*)
    49        2.6259  rbx                      rubinius::VariableScope::get_local(int)

After:

    samples  %        app name                 symbol name
    2678     27.2764  rbx                      rubinius::MachineCode::interpreter(rubinius::State*, rubinius::MachineCode*, rubinius::InterpreterCallFrame*)
    2459     25.0458  8685.jo                  _X_Object#forever$block@1
      # => Wow, the name of JIT-ted Ruby code is shown along side C++ function symbols!
    771       7.8529  rbx                      rbx_set_local_depth
    661       6.7325  rbx                      rubinius::BlockEnvironment::call(rubinius::State*, rubinius::CallFrame*, rubinius::Arguments&, int)
    650       6.6205  rbx                      __x86.get_pc_thunk.bx
    564       5.7446  rbx                      rbx_push_local_depth
    398       4.0538  rbx                      rubinius::BlockEnvironment::invoke(rubinius::State*, rubinius::CallFrame*, rubinius::BlockEnvironment*, rubinius::Arguments&, rubinius::BlockInvocation&)
    349       3.5547  rbx                      rubinius::VariableScope::set_local(int, rubinius::Object*)
    256       2.6075  rbx                      rubinius::VariableScope::set_local(rubinius::State*, int, rubinius::Object*)
    254       2.5871  rbx                      rubinius::VariableScope::get_local(int)
    241       2.4547  rbx                      bool rubinius::kind_of<rubinius::Fiber>(rubinius::Object const*)
    210       2.1389  rbx                      rubinius::SharedState::checkpoint(rubinius::ManagedThread*)

In short, you can tell how Rubinius' JIT works in performance point of view.

Not satified yet? Even annotated profile is supported! That means you can even
know how much it spends on each line of Ruby code or even on each CPU
instructions:

    /* 
     * Total samples for file : "/tmp/loop.rb"
     * 
     *   4911 19.7689
     */


       665  2.6769 :def increment(i)
       373  1.5015 :  i + 1
                   :end
                   :
                   :def forever
                   :  i = 0
      2668 10.7399 :  loop do /* _X_Object#forever$block@1 total:   6184 24.8933 */
      1205  4.8507 :    i = increment(i)
                   :  end
                   :end
                   :
                   :forever

We're using OProfile, a profiling software. By this blog post, I'll show you
how to profile using it!

### What's OProfile?

It's a very useful profiling tool available on Linux. It's a sampling-based
one. That means there is absolutely no change to Rubinius and your Ruby code to
profile. Just run it as you normally do. Also, the overhead of profile is
 minimal.

This is contrasted to measuing-based profiling. Ruby's built-in profiler
 belongs to it. And you should be aware of the way-too-much overhead. ;)

Basically, it works by reporting how many individual profiled items are sampled
compared to the overall total samples. It doesn't measure elapsed time. It's
much like top command's indivisual processes' CPU % usage with far greater
flexibility. The actual profiled items can be any of C/C++ libraries, C/C++
functions, C/C++ source code lines, or CPU instructions.

So, OProfile can't usually profile Ruby code because it works on CPU
instruction level. From OProfile, it can't tell which Ruby source code line
Rubinius currently executing from the CPU instrucitons. However, it can profile
JIT-ted Ruby code because Rubinius compiles it very down into the CPU
instructions by definition.

OProfile works as a Linux kernel module. So, it's supported only for Linux.
Sadly, Ubuntu's OProfile and LLVM have bugs relating to this feature.
Apparently, there is no one using this. In a say, we are really on the cutting
edge. ;)

Anyway, we must overcome it. But how? You have options. :)

### Setup (PPA: the super simple way; Ubuntu 12.10 only)

I prepared a [PPA](https://launchpad.net/~ryoqun/+archive/ppa) just for you.
Add it to your system. To be specific, run this:

    $ sudo add-apt-repository ppa:ryoqun/ppa
    $ sudo apt-get update
    $ sudo apt-get install oprofile llvm-3.1
    $ sudo apt-get dist-upgrade # Upgrade preinstalled libllvm3.1 to the PPA

By default, Rubinius doesn't use system-provided LLVM, so re-configure Rubinius
to use it and re-build Rubinius:

    $ cd path/to/rubinius-git-repository
    $ rake clean
    $ ./configure --llvm-config llvm-config-3.1
    $ rake

Done!

### Setup (manual build: the hard way)

If you really want to build LLVM and OProfile manually or if you're using an
other Linux distribution and the distribution doesn't provide OProfile-enabled
 LLVM packages, manually build LLVM and OProfile like this:

(I tested this on Ubuntu 12.10. Minor adjustments may be needed to build on
your environment)

Build and Install OProfile:

    $ sudo apt-get build-dep oprofile # do equivalent thing on your distro.
    $ cd /path/to/working-dir-to-build-things
    $ wget http://prdownloads.sourceforge.net/oprofile/oprofile-0.9.8.tar.gz
    $ tar -xf oprofile-0.9.8.tar.gz
    $ cd oprofile-0.9.8
    $ ./autogen.sh
    $ ./configure --prefix /usr # LLVM has a build issue. So install to /usr
    $ make
    $ sudo make install
    $ adduser oprofile # this is needed for profiling JITted code
    $ opreport --version
      # => opreport: oprofile 0.9.8 compiled on Mar  8 2013 00:57:08

Force to build LLVM with OProfile support enabled and rebuild Rubinius:

    $ sudo apt-get build-dep llvm # do equivalent thing on other distributions.
    $ cd /path/to/working-dir-to-build-things
    $ wget http://llvm.org/releases/3.2/llvm-3.2.src.tar.gz
    $ tar -xf llvm-3.2.src.tar.gz
    $ cd llvm-3.2.src
    $ ./configure --enable-optimized --disable-assertions --with-oprofile
    $ make
    $ sudo make install

If the compilation of OProfileWrapper.cpp fails like this:

    OProfileWrapper.cpp: In member function ‘bool llvm::OProfileWrapper::checkForOProfileProcEntry()’:
    OProfileWrapper.cpp:141:62: error: ‘read’ was not declared in this scope
    OProfileWrapper.cpp:142:24: error: ‘close’ was not declared in this scope

Apply this patch and re-`make` and continue:

    diff --git a/lib/ExecutionEngine/OProfileJIT/OProfileWrapper.cpp b/lib/ExecutionEngine/OProfileJIT/OProfileWrapper.cpp
    index d67f537..7c0d395 100644
    --- a/llvm-3.1-3.1/lib/ExecutionEngine/OProfileJIT/OProfileWrapper.cpp
    +++ b/llvm-3.1-3.1/lib/ExecutionEngine/OProfileJIT/OProfileWrapper.cpp
    @@ -29,6 +29,7 @@
     #include <dirent.h>
     #include <sys/stat.h>
     #include <fcntl.h>
    +#include <unistd.h>
     
     namespace {
     

Phew, finally rebuild Rubinius!:

    $ cd path/to/rubinius-repository
    $ rake clean
    $ rm -rf vendor/llvm # If you build Rubinius with vendorized LLVM.
    $ ./configure
    $ rake

### Start OProfile

OProfile can be configured by a command called `opcontrol`, not by a
configuration file, which are common.

    $ sudo opcontrol --deinit
    $ sudo modprobe oprofile timer=1      # Needed only inside VirtualBox VMs
    $ echo 0 | sudo tee /proc/sys/kernel/nmi_watchdog
    $ sudo opcontrol --no-vmlinux
    $ sudo opcontrol --separete all
    $ sudo opcontrol --start
    $ sudo opcontrol --dump               # Flushes buffered raw profile data
    $ opreport --merge all --threshold 1  # Prints the report of profile

Setup is complete if you see an output from opreport like this:

    CPU: CPU with timer interrupt, speed 1858.39 MHz (estimated)
    Profiling through timer interrupt
              TIMER:0|
      samples|      %|
    ------------------
        92127 67.6157 no-vmlinux
        21920 16.0880 rbx
         7950  5.8348 libc-2.15.so
         4068  2.9857 runner
         3429  2.5167 libstdc++.so.6.0.17
         2139  1.5699 cc1
         1416  1.0393 vm

Congratulations!

### Run Ruby code!

To annotate Ruby code correctly, your current directory must be the top
directory of the Rubinius git repository:

    $ cd path/to/rubinius-git-repository
    $ ./bin/benchmark ./benchmark/core/hash/bench_access.rb

### Generate profile report

Let's check the profile report of the above benchmark.

    $ sudo opcontrol --dump && sudo opjitconv /var/lib/oprofile/ 0 0
    $ opreport --merge all --threshold 1 image:bin/rbx --symbols \
        > /tmp/hash-access-symbols
    $ opannotate --merge all --threshold 1 image:bin/rbx --source \
        > /tmp/hash-access-source

I'll omit but you can generate profile report of annotated assembly by passing
`--assembly` to `opannotate` instead of `--source`.

### Reset current profile

By default, OProfile keeps the profile data indefinitely. To reset it, run
this:

    $ sudo opcontrol --reset

### How to read the profile result

Open `/tmp/hash-access-symbols`, the content should be like this:

    CPU: CPU with timer interrupt, speed 1861.31 MHz (estimated)
    Profiling through timer interrupt
    samples  %        app name                 symbol name
    10760    28.4807  no-vmlinux               /no-vmlinux
    1456      3.8539  rbx                      __x86.get_pc_thunk.bx
    948       2.5093  rbx                      rbx_set_local_depth
    880       2.3293  libc-2.15.so             /lib/i386-linux-gnu/libc-2.15.so
    864       2.2869  rbx                      rubinius::Object::hash(rubinius::State*)
    834       2.2075  rbx                      jit_stub_object_hash
    831       2.1996  rbx                      rubinius::Tuple::put(rubinius::State*, int, rubinius::Object*)
    683       1.8078  rbx                      rbx_push_local_depth
    676       1.7893  5626.jo                  _X_Object#__block__$block@7
    653       1.7284  5647.jo                  _X_Object#__block__$block@11
    651       1.7231  rbx                      rubinius::InlineCache::check_cache_poly(rubinius::State*, rubinius::InlineCache*, rubinius::CallFrame*, rubinius::Arguments&)
    639       1.6914  rbx                      rubinius::CompiledCode::specialized_executor(rubinius::State*, rubinius::CallFrame*, rubinius::Executable*, rubinius::Module*, rubinius::Arguments&)
    632       1.6728  5586.jo                  _X_Object#__block__$block@11
    630       1.6675  5586.jo                  _X_Object#__block__$block@1
    630       1.6675  5647.jo                  _X_Object#__block__$block@7
    616       1.6305  5586.jo                  _X_Object#__block__$block@7
    607       1.6067  5626.jo                  _X_Object#__block__$block@1
    593       1.5696  5647.jo                  _X_Object#__block__$block@1
    591       1.5643  5626.jo                  _X_Object#__block__$block@10
    590       1.5617  rbx                      rubinius::VariableScope::get_local(int)
    554       1.4664  rbx                      rubinius::VariableScope::set_local(rubinius::State*, int, rubinius::Object*)
    436       1.1540  5626.jo                  _X_Hash#values_at@18
    434       1.1488  rbx                      rubinius::Object::hash_prim(rubinius::State*)
    391       1.0349  rbx                      rubinius::VM::new_young_tuple_dirty(unsigned int)

As you can guess, symbol names beginning with `_X_` is the JIT-ted Ruby code.
While many Ruby blocks are JIT-ted, we can't know much about from its mere
names. On the other hand,  `_X_Hash#values_at@18` is obviously a JIT-ted
code of `Hash#values_at`. I'll explain the format of the report using it as an
example:

    436       1.1540  5626.jo                  _X_Hash#values_at@18

`436` is the number of counts OProfile found what Rubinius was executing, while
periodically sampling it.

`1.1540` is the percentage to the total number of samples OProfile collected.
Note that summing all entries up doesn't equal to 100%, because `opreport` only
reported the top part of whole profile result (by `--threshold 1`).

`5626.jo` means this is JIT-ted code created when running process of PID 5526.

`_X_Hash#values_at@18` is the name of symbol for this entry of profile report
(duh!).

Open `/tmp/hash-access-source`, the content should be like this (I'll omit some
unimportant part, because this file is big):

    /* 
     * Total samples for file : "kernel/common/hash18.rb"
     * 
     *   4870 12.8904
     */

    <credited to line zero>     19  0.0503 :
                   :# -*- encoding: us-ascii -*-
                   :
                   :class Hash
                   :
                   :  include Enumerable
                   :
    ...
                   :
                   :  class Bucket
                   :    attr_accessor :key
                   :
       633  1.6755 :    def match?(key, key_hash) /* _X_Hash::Bucket#match?@16     75  0.1985, _X_Hash::Bucket#match?@16     45  0.1191, total:    120  0.3176 */
        40  0.1059 :      case key
       218  0.5770 :      when Symbol, Fixnum
       319  0.8444 :        return key.equal?(@key)
                   :      end
                   :
                   :      @key_hash == key_hash and (Rubinius::Type::object_equal(key, @key) or key.eql?(@key))
                   :    end
                   :  end
    ...
                   :end
    ...

You might wonder why Hash::Bucket#match? has so many counts while this didn't
appear in the report for symbols. The reason is that the method is inlined to
each its callers (maybe many top-appearing JIT-ted Ruby blocks). How cool this
is! You can really know which Ruby code is actually taking too much time.

### My last favor

I wish the official Ubuntu packages are fixed and there is no need to add any
PPA. I want it-just-works. I reported affecting bugs to Ubuntu's bug tracking
system. So, please vote it up for fixing (vote them with "affects you?",
please!!):

- [Bug 1154025](https://launchpad.net/bugs/1154025) Install PIC version of libbfd.a
- [Bug 1148682](https://launchpad.net/bugs/1148682) symbol lookup error: /usr/lib/libopagent.so: undefined symbol: bfd_init
- [Bug 1148529](https://launchpad.net/bugs/1148529) OProfile support is disabled

### Further profiling

There is new proling tool on Linux: `perf` and `operf` (OProfile's new
command). I don't know them well, but certainly they will be useful for
profiling Rubinius.

Happy profiling!
