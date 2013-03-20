---
layout: post
title: Profiling JIT-ted Ruby code with OProfile
author: Ryo Onodera
---

You can now profile JIT-ted Ruby code!

Before:

After:

In short, you can tell how Rubinius' JIT works.

Not satified yet? Even annotated profile is supported! That means you can even know how much it spends on each line of Ruby code or on each CPU instructions.

Before:

After:

For this, we're using OProfile, a profiling software.

### What's OProfile?

It's a very useful profiling tool available on Linux. It's a sampling-based one. That means there is absolutely no change to Rubinius and your Ruby code to profile. Just run it as you normally do. Also, the overhead of profile is minimal.

This is constrasted to measuing-based profiling. Ruby's built-in profiler belongs to it. And you should be the way-too-much overhead. ;)

OProfile works as a Linux kernel module. So, it's only supported for Linux. Basically, it can report how many individual profiled items are sampled compared to the overall total samples. It doesn't measure elapsed time. It's much like top command's indivisual processes' CPU usage with far greater flexibility. The actual profiled items can be any of C libraries, C functions, C source code lines, or machine instructions.

So, OProfile can't usually profile Ruby code because it works on machine instruction level. From OProfile, it can't tell which Ruby source code line Rubinius currently executing from the machine instrucitons. However, it can profile JIT-ted Ruby code because Rubinius compiles Ruby code very down into the machine instructions by definition.

Sadly, Ubuntu's OProfile and LLVM have bugs relating to this feature. Apparently, there is no one using this. In a say, we are really on the cutting edge. ;)

Anyway, we must overcome it. But how? You have options. :)

### Setup (the super simple way; Ubuntu 12.10 only)

I prepared a PPA (https://launchpad.net/~ryoqun/+archive/ppa) just for this. Add it to your system. To be specific, run this:

$ sudo add-apt-repository ppa:ryoqun/ppa
$ sudo apt-get update
$ sudo apt-get install oprofile llvm-3.1
$ sudo apt-get dist-upgrade # Upgrade preinstalled libllvm3.1 to my PPA version

By default, Rubinius doesn't use system-provided LLVM, so re-configure Rubinius to use it and re-build:

$ cd path/to/rubinius-git-repository
$ ./configure --llvm-config llvm-config-3.1
$ rake

Done!

### Setup (the super hard way)

if you're not using Ubuntu, but other Linux distributions and the distribution doesn't provide Oprofile-enabled LLVM packages,
If you really want to build LLVM and OProfile manually, do this:

I tested this on Ubuntu 12.10. Minor adjustments may be needed to build on your environment.

Build and Install OProfile

    $ sudo apt-get build-dep oprofile # do equivalent thing on other distributions.
    $ cd /path/to/working-directory-to-build-things
    $ wget http://prdownloads.sourceforge.net/oprofile/oprofile-0.9.8.tar.gz
    $ tar -xf oprofile-0.9.8.tar.gz
    $ cd oprofile-0.9.8
    $ ./autogen.sh
    $ ./configure --prefix /usr
    $ make
    $ sudo make install
    $ opreport --version
    # it says like this: opreport: oprofile 0.9.8 compiled on Mar  8 2013 00:57:08

Force to build LLVM with OProfile support enabled and rebuild Rubinius

    $ wget http://llvm.org/releases/3.2/llvm-3.2.src.tar.gz
    $ tar -xf llvm-3.2.src.tar.gz
    $ cd llvm-3.2.src
    $ ./configure --enable-optimized --disable-assertions --with-oprofile
    $ make
    $ sudo make install

If compilation of OProfileWrapper.cpp fails, apply this patch:

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
   

### Setup OProfile

OProfile can be configured by a command called oprofile, not by a configuration
file.

    $ sudo opcontrol --deinit
    $ sudo modprobe oprofile timer=1      # Use only when running in VirtualBox
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

Congurationlations!

### Run Ruby code!

### Generate profile report

To annotate Ruby code correctly, your current directly must be the top directory of the Rubinius git repository.

$ sudo opcontrol --dump && sudo opjitconv /var/lib/oprofile/ 0 0
$ opreport --merge=all --symbols image:bin/rbx
$ opannotate --source

I'll omit but you can generate profile report of annotated assemble by passing --assembly to opannottate instead of --source

### Reset current profile

$ sudo opcontrol --reset

### How to read the profile result

### My last favor

I wish the official packages are fixed and there is no need to add any PPA. I want it-just-works. I reported affecting bugs to Ubuntu's bug tracking system. So, please vote it up for fixing!(Please, vote them with "affects you?"!!):

Bug 1154025 Install PIC version of libbfd.a
Bug 1148682 symbol lookup error: /usr/lib/libopagent.so: undefined symbol: bfd_init
Bug 1148529 OProfile support is disabled


### Further profiling

There is new proling tool on Linux: perf and operf (OProfile's new command). I don't know them well, but certainly they will be useful for profiling Rubinius.




It's now **[very easy](https://github.com/rubinius/heroku-rbx-puma-rails-app)** to get a [Rails app](https://devcenter.heroku.com/articles/rails3) on [Heroku's Cedar Stack](https://devcenter.heroku.com/articles/cedar) running on [Rubinius 2.0](http://rubini.us "Rubinius : Use Ruby&#8482;") and [Puma 2.0](http://puma.io "A Modern, Concurrent Web Server for Ruby - Puma").


### The Backstory

The fine folks at Heroku have been adding support for using [Bundler](http://gembundler.com "Bundler: The best way to manage a Ruby application's gems") to [specify which version of Ruby](https://devcenter.heroku.com/articles/ruby-versions) your app uses and even [to specify which Ruby](https://blog.heroku.com/archives/2012/12/13/run_jruby_on_heroku_right_now) it uses.

I've checked in on the progress of using Rubinius with this same method every couple few months for the past year or so. I was always met with the same results... <q>"not quite yet, we're working on it"</q>.

Last night I was getting mentally packed for [Waza](https://waza.heroku.com/2013) later this week and decided to check in on the state of things so I could ask the right people the right questions in person when we're all together. Turns out that sometime between last time and this time, they've got things working. Boom diggity! And it's pretty ding-dang easy too! Double boom diggity!


### The Build Up

I'm going to assume that if you want to use Rubinius 2.0 that you also have the good sense to want to use Puma 2.0. There are three very simple steps to get up and running with Rubinius 2.0 + Puma 2.0.

#### Step 1

Add the Puma gem to your `Gemfile`.

<script src="https://gist.github.com/veganstraightedge/5041441.js"></script>


#### Step 2

Tell Heroku to use Puma as your web server in your `Procfile`.

<script src="https://gist.github.com/veganstraightedge/0135a61335bc76b1d9d5.js"></script>

#### Step 3

Specify Rubinius as your Ruby engine in your `Gemfile`.

<script src="https://gist.github.com/veganstraightedge/1fb7ff88e74567c6e2e6.js"></script>


### The Breakdown

Once you've done those things, your workflow is the same as before.
`bundle update && git commit -am "Double boom diggity!" && git push heroku master`

If you're changing an existing app from Heroku's default Ruby (MRI 1.9.x) to Rubinius, you'll see a message like this when you `git push heroku master`.

<script src="https://gist.github.com/veganstraightedge/5041986.js"></script>

The important lines are `Old: ruby 1.9.3` and `New: rubinius 2.0.0.rc1`. After that, everything the same as before. The bundling starts, etc.


### The Outro

That's it. You should now be up and running with Rubinius and Puma!

If you have problems, say something in the comments with a link to a gist with your problem output. If you succeed and get up and running in production, let us in the comments too. Tell the world that you love Rubinius/Puma.

I threw together this [quick and dirty Rails app](https://github.com/rubinius/heroku-rbx-puma-rails-app) from scratch deployed to Heroku to show all this in action. [http://heroku-rbx-puma-rails-app.herokuapp.com](http://heroku-rbx-puma-rails-app.herokuapp.com "Using Rubinius &amp; Puma on Heroku"). I also migrated an existing MRI 1.9.3 app ( [The Farmhouse site](http://farmhouse.la "The Farmhouse in Hollywood, California") ) to Rubinius 2.0 to show the migration is easy too.


### The Thank Yous

None of this would be possible without the hard work of [Carl Lerche](https://github.com/carllerche), [Yehuda Katz](https://github.com/wycats/), [André Arko](https://github.com/indirect/), [Terrence Lee](https://github.com/hone) and the other contributors to [Bundler](https://github.com/carlhuda/bundler). And a special thanks to Terrence Lee for his dutiful stewardship of the [Heroku Ruby Buildpack](https://github.com/heroku/heroku-buildpack-ruby/). Once again, the awesome powers of Open Source make great things possible.


### The Footnotes

As of this writing "Rubinius 2.0" actually means "Rubinius 2.0.0.dev" and "Puma 2.0" actually means "Puma 2.0.0b6". The net result is the same though.

