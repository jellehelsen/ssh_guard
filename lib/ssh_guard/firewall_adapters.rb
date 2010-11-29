module SshGuard
  module FirewallAdapters
    class IPFWAdapter
      def block_host(host)
        `ipfw add deny tcp from #{host} to me ssh`
      end
    end
  end
end
