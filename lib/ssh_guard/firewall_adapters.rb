module SshGuard
  module FirewallAdapters
    class IPFWAdapter
      def initialize
        @logger    = Logger.new(STDOUT)
      end
      def block_host(host)
        unless blocked?(host)
          `ipfw add 100 deny tcp from #{host} to me ssh`
          @logger.warn("Blocking host #{host}!")
        end
      end
      
      def blocked?(host)
        `ipfw list | grep "deny tcp from #{host} to me dst-port 22"` =~ /deny tcp from #{host} to me dst-port 22$/ ? true : false
      end
    end
  end
end
