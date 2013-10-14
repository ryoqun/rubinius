require 'nokogiri'
require 'pygments.rb'
require 'graphviz'
require 'cgi'

doc = Nokogiri.parse(Pygments.highlight(<<SRC, :lexer => 'llvm', :options => {:noclasses => true}))
; Declare the string constant as a global constant.
@.str = private unnamed_addr constant [13 x i8] c"hello world"

; External declaration of the puts function
declare i32 @puts(i8* nocapture) nounwind

; Definition of main function
define i32 @main() {   ; i32()*
  ; Convert [13 x i8]* to i8  *...
  %cast210 = getelementptr [13 x i8]* @.str, i64 0, i64 0

  ; Call puts function to write out the string to stdout.
  call i32 @puts(i8* %cast210)
  ret i32 0
}

; Named metadata
!1 = metadata !{i32 42}
!foo = !{!1, null}
SRC
COLOR = /#[0-9A-F]{6}/i

class Downgrader
  def initialize(root)
    @root = root
    @buf = ""
  end

  def transform(node=@root)
    close = ""
    case node
    when Nokogiri::XML::Document
      #p node
    when Nokogiri::XML::Text
      @buf << CGI.escapeHTML(node.text).gsub(/\n/, "<BR ALIGN=\"LEFT\"/>")
    when Nokogiri::XML::Element
      case node.name
      when "pre"
      when "div"
        #@buf << "<FONT FACE=\"M+ 1mn\"><TABLE BORDER=\"1\" CELLBORDER=\"0\" CELLSPACING=\"0\" BGCOLOR="
        #@buf << node.attributes["style"].value[COLOR].inspect
        #@buf << "><TR><TD>"
        #close += "</TD></TR>" #</TABLE></FONT>"
      when "span"
        @buf << "<FONT COLOR="
        @buf << node.attributes["style"].value[COLOR].inspect
        #node.attributes.inspect.display(STDERR)
        @buf << ">"
        if node.attributes["style"].value[/font-weight: bold/i]
          @buf << "<B>"
          close = "</B>" + close
        end
        if node.attributes["style"].value[/font-style: italic/i]
          @buf << "<I>"
          close = "</I>" + close
        end
        close += "</FONT>"
      else
        p node.name
      end
    else
      p node.class
    end
    node.children.each do |child|
      transform(child)
    end
    @buf << close

    @buf
  end
end

dot = <<E
digraph structs {
    node [shape=plaintext]
    struct1 [label=<
#{Downgrader.new(doc).transform}
>];
}
E

#puts dot

def parse_structure(text)
  open = ""
  close = ""
  body = ""
  first = true
  close_tags = []
  colspan = 0
  colspan_magic = 777
  puts
  text.split(/([{\|}]|[^{}\|]+)/).reject(&:empty?).tap{|a|}.each do |token|
    case token
    when "{"
      if first
        open.concat("<TR>")
        close.prepend("</TR>")
      else
        close.concat("<TR>")
        close_tags.push("</TR>")
      end

    when "|"
      if first
        first = false
        close.prepend("</TD>")
      end
      close.concat(close_tags.pop || "")
    when "}"
      close.concat(close_tags.pop || "")
    else
      if first
        open.concat("<TD COLSPAN=\"777\">")
        body = token
      else
        if token[/^<([^<>]+?)>/]
          #p $1
          close.concat("<TD PORT=\"#{$1}\">")
          close.concat(CGI.escape_html(token[token[/^<([^<>]+?)>/].size..-1]))
        else
          close.concat("<TD>")
          close.concat(CGI.escape_html(token))
        end
        colspan += 1
        close_tags.push("</TD>")
      end
    end
  end
  if first
    close.prepend("</TD>")
  end

  [open.sub(/777/, colspan.to_s), body, close]
end

GraphViz.parse(ARGV.first, :path => "/home/ryoqun/rubinius/ryoqun/") do |graph|
  #p graph.methods - Object.new.methods.sort
  #first = 0
  graph.each_node do |node|
    graph.get_node(node) {|n|
     #sleep 1
     #if first < 15
     #  first += 1




       label = n[:label].instance_variable_get(:@data).gsub(/\\l/,"\n").gsub(/\\>/, ">").gsub(/\\</, "<")#.gsub(/\|{<s0>T\|<s1>F}}$/, '').gsub(/^{/, '').gsub(/}$/, '')
       open, body, close = parse_structure(label)
       #label = label.gsub(/%"struct.rubinius::([a-zA-Z]+?)"/, '%\1').gsub(/, !dbg.*$/, '')
       body = body.gsub(/%"struct.rubinius::([a-zA-Z]+?)"/, '%\1').gsub(/, !dbg.*$/, '')
       #puts label

#s = "%return_phi = phi %\"struct.rubinius::Object\"* [ %ret, %arg_error ], [ %kind_of, %use_call ], [ inttoptr (i64 18 to %\"struct.rubinius::Object\"*), %is_false_block ], [ inttoptr (i64 18 to %\"struct.rubinius::Object\"*), %is_true_block ], [ inttoptr (i64 18 to %\"struct.rubinius::Object\"*), %is_nil_block ], [ inttoptr (i64 18 to %\"struct.rubinius::Object\"*), %is_fixnum_block ], [ inttoptr (i64 18 to %\"struct.rubinius::Object\"*), %is_symbol_block ], [ inttoptr (i64 18 to %\"struct.rubinius::Object\"*), %reference_block ], [ inttoptr (i64 18 to %\"struct.rubinius::Object\"*), %is_fixnum_block ]"
      body.gsub! /^.* = phi %.+$/ do |phi|
        t = phi[/^.* phi .+?(?= \[)/]
        r = phi[t.size..-1]
        buf = ""
        r.split(/( \[ .*? \],)/).reject(&:empty?).each_with_index do |arg, index|
          if index.zero?
            buf << "#{t}#{arg}\n"
          else
            buf << "#{" " * t.size}#{arg}\n"
          end
        end
        buf
      end

      body.gsub! /^.* = call %.+$/ do |phi|
        t = phi[/^.* call .+?(?=\(%)/]
        r = phi[t.size..-1]
        buf = ""
        r.split(',').reject(&:empty?).each_with_index do |arg, index|
          if index.zero?
            buf << "#{t}#{arg}\n"
          else
            buf << "#{" " * t.size}#{arg}\n"
          end
        end
        buf
      end
#r.split(/( \[ .*? \],)/).reject(&:empty?).each_with_index do |arg, index|
#  if index.zero?
#    puts "#{t}#{arg}"
#  else
#    puts "#{" " * t.size}#{arg}"
#  end
#end

       high = Pygments.highlight(body, :lexer => 'llvm', :options => {:noclasses => true})
       doc = Nokogiri.parse(high)
       #n[:label] = "<#{Downgrader.new(doc).transform}>"
       body = "#{Downgrader.new(doc).transform}"

        #@buf << "<FONT FACE=\"M+ 1mn\"><TABLE BORDER=\"1\" CELLBORDER=\"0\" CELLSPACING=\"0\" BGCOLOR="
        #@buf << node.attributes["style"].value[COLOR].inspect
        #@buf << "><TR><TD>"
        #close += "</TD></TR>" #</TABLE></FONT>"
       result = "<FONT FONTSIZE=\"124\" FACE=\"M+ 1mn\"><TABLE BORDER=\"1\" CELLSPACING=\"0\">#{open + "#{body}" + close}</TABLE></FONT>"
       #puts result
       result = "<#{result}>"
       n[:label] = result
       n[:shape] = "plaintext"
       #n[:label] = doc.text.strip #"<#{Downgrader.new(doc).transform}>"
     #end
    }
  end
end.output(File.extname(File.basename(ARGV.last))[1..-1].to_sym => ARGV.last)
