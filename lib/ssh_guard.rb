$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'ssh_guard'))
require "database"
require "firewall_adapters"
module SshGuard
  class Core
    attr_reader :database
    attr_reader :firewall
    class Parser
      def parse_line(line)
        if line =~ /Did not receive identification string/ || line =~ /POSSIBLE BREAK-IN ATTEMPT!/
          ip_address = line.match(/\d+\.\d+.\d+.\d+/).to_s
          timestamp = Time.parse(line.match(/(^.+) mini/)[1])
          {:ip_address => ip_address, :timestamp => timestamp}
        end
      end
    end

    def initialize
      @database = Database.new
      @parser = Parser.new
      @firewall = FirewallAdapters::IPFWAdapter.new
    end

    def <<(line)
      if entry = @parser.parse_line(line)
        database.add_entry(entry)
        if database.should_block? entry[:ip_address]
          firewall.block_host entry[:ip_address]
        end
      end
    end
  end
end
