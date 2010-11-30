$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'ssh_guard'))
require "logger"
require "database"
require "firewall_adapters"
module SshGuard
  class Core
    attr_reader :database
    attr_reader :firewall
    class Parser
      def parse_line(line)
        if line =~ /Did not receive identification string/ || line =~ /POSSIBLE BREAK-IN ATTEMPT!/ || line =~ /invalid user/i || line =~ /authentication error/
          ip_address = line.match(/\d+\.\d+.\d+.\d+/).to_s
          timestamp = Time.parse(line.match(/(^.+) mini/)[1])
          {:ip_address => ip_address, :timestamp => timestamp}
        end
      end
    end

    def initialize
      unless i_am_root?
        raise "ssh_guard should be started as root!!!"
      end
      @database = Database.new
      @parser   = Parser.new
      @firewall = FirewallAdapters::IPFWAdapter.new
      @log_file = "secure.log"
    end

    def <<(line)
      if entry = @parser.parse_line(line)
        if database.should_block? entry[:ip_address]
          firewall.block_host entry[:ip_address] unless firewall.blocked?(entry[:ip_address])
        else
          database.add_entry(entry) unless firewall.blocked?(entry[:ip_address])
        end
      end
    end
    
    def start
      IO.popen("tail -f #{@log_file}") do |f|
        while line = f.gets
          self << line if line =~ /sshd/
        end
      end
    end
    
    def self.i_am_root?
      `whoami` =~ /^root$/
    end
    def i_am_root?
      self.class.i_am_root?
    end
  end
end
