require 'erb'

def dnsmasq_read(fname)
  options = {}
  begin
    f = File.open(fname, 'r')
  rescue
      puts "Could not open dnsmasq config file."
      return options
  end

  @port_forwards = []
  f.each do |line|
    if line.match /\s*#/ then
      next
    end
    p line
    m = line.match /\s*([\w\-]+)\s*\=\s*([\w\d\.\/\,]+)\s*/
    if m then
      puts "match equal #{m[1]} #{m[2]}"
      options[m[1]] = m[2]
      next
    end

    m = line.match /\s*([\w\-]+)\s*/
    options[m[1]] = 1 if m
    p "match one #{m[1]}"
  end
  f.close
  return options
end

def dnsmasq_write(fname, o)
  f = File.open(fname, 'w')
  f.print "# Listening on interface\n"
  f.print "interface=#{o[:interface]}\n"
  f.print "# DNS Port (default 53), 0 disables DNS server\n"
  f.print "#port=53\n"
  f.print "# Use PPP upstream servers\n"
  f.print "resolv-file=/etc/ppp/resolv.conf\n" if "true".eql? o[:dnssource]
  f.print "# DNS Server used\n"
  f.print "server=#{o[:dnsserver]}\n"
  f.print "# Expand Hosts with domain ending\n"
  f.print "expand-hosts\n" if "true".eql? o[:expand]
  f.print "# Local-only domains answered from /etc/host or DHCP\n"
  f.print "local=/#{o[:local]}/\n" if "true".eql? o[:expand]
  f.print "# Domain\n"
  f.print "domain=#{o[:domain]}\n"
  f.print "# Read /etc/ethers for MAC->Hostname mapping\n"
  f.print "read-ethers\n" if "true".eql? o[:ethersource]
  f.print "# DHCP Range offered and lease time\n"
  f.print "dhcp-range=#{o[:dhcpminrange]},#{o[:dhcpmaxrange]},12h\n"
  f.print "# Specifies which DNS servers are offered to clients\n"
  f.print "dhcp-option=6,#{o[:dns4advert]}\n"
  f.print "# Specifies which IPv6 DNS servers are offered to clients\n"
  f.print "dhcp-option=option6:dns-server,[#{o[:dns6advert]}]\n" if not o[:dns6advert].empty?
  f.close
end
