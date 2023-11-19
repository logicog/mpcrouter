require 'erb'


def nftable_read(f)
  port_forwards = []
  options = { }
  
  puts "nftable_read OPENING file #{f}"
  
  begin
    nft_file = File.open(f, 'r')
  rescue
    return [port_forwards, options]
  end

  nft_file.each do |line|
    m = line.match /\s*define\s+(\w+)\s+\=\s+([\w\d\.\/]+)\s*/
    if m then
      puts "#{m[1]} #{m[2]}" if "LAN_DEV".eql? (m[1])
      options[:landev] = m[2] if "DEV_LAN".eql? (m[1])
      options[:wandev] = m[2] if "DEV_WAN".eql? (m[1])
      options[:ownip] = m[2] if "PRIVATE_IP".eql? (m[1])
      options[:lan] = m[2] if "NET_PRIVATE".eql? (m[1])
    end
# Matches reflection
#    m = line.match /\s*ip\s+saddr\s+\$NET_PRIVATE\s+ip\s+daddr\s+\$PUBLIC_IP\s+tcp\s+dport\s+(\d+)\s+dnat\s+ip\s+to\s+([\d\.]+):(\d+)\s+comment\s+(.*)/
#     port_forwards.push( { :rule => m[5], :dport => m[1], :host => m[2], :port => m[3] } )
    m = line.match /\s+meta\s+nfproto\s+ipv4\s+(\w\w\w)\s+dport\s+(\d+)\s+counter\s+name\s+\w+\s+dnat\s+ip\s+to\s+([\d\.]+):(\d+)\s+comment\s+\"(.*)\".*/
                    p m if m
    if m then
  #    puts "#{m[1]} #{m[2]} #{m[3]} #{m[4]}"
      port_forwards.push( { :rule => m[5], :dport => m[4], :host => m[3], :port => m[2], :protocol => m[1] } )
    end
  end
  nft_file.close
  
  [ port_forwards, options ]
end

def nftable_write(f, port_forwards, options)

  p options
  nft_template = ERB.new  <<-EOF
#!/usr/sbin/nft -f

flush ruleset

# enp2s0 is lan, ppp1 is wan, lan is 192.168.1.0
define DEV_LAN = <%=options[:landev]%>
define DEV_WAN = <%=options[:wandev]%>
define NET_PRIVATE = <%=options[:lan]%>
define PUBLIC_IP =  <%=options[:public_ip]%>
define PRIVATE_IP = <%=options[:ownip]%>

table inet mpcfw {
	counter cnt_lan_in {
		comment "Inbound LAN traffic"
	}
	
	counter cnt_lan_out {
		comment "Traffic leaving LAN"
	}
	
	counter cnt_fwd_wan_out {
		comment "Traffic to WAN"
	}
	
	counter cnt_fwd_wan_in_reject {
                comment "Traffic rejected coming from WAN"
        }
	
	counter cnt_fwd_wan_out_reject {
		comment "Traffic rejected going to WAN"
	}
	
        chain input {
                type filter hook input priority filter; policy accept;
                # Accept loopback traffic
                iifname "lo" accept
                # Accept inbound established and related flows
                ct state established,related accept
                # Rate limit TCP syn packets
                tcp flags syn / fin,syn,rst,ack jump syn_flood
                # Handle lan/wan input traffic
                iifname vmap { $DEV_WAN : jump input_wan, $DEV_LAN : jump input_lan }
        }

        chain forward {
                type filter hook forward priority filter; policy drop;
                # Allow forwarded established/related flows
                ct state established,related accept
                # Forward lan/wan traffic
                iifname vmap { $DEV_WAN : jump forward_wan, $DEV_LAN : jump forward_lan }
                jump handle_reject
        }

        chain output {
                type filter hook output priority filter; policy accept;
                # Accept traffic to loopback
                oifname "lo" accept
                ct state established,related accept
                # Handle output traffic
                oifname vmap { $DEV_LAN : jump output_lan, $DEV_WAN : jump output_wan }
        }

        chain prerouting {
                type filter hook prerouting priority filter; policy accept;
                # Handle lan IPv4/IPv6 helper assignment
                iifname $DEV_LAN jump helper_lan
        }

        chain handle_reject {
                # Reject TCP traffic
                meta l4proto tcp reject with tcp reset
                # Reject any other traffic
                reject
        }

        chain syn_flood {
                # Accept SYN packets up to rate limit
                limit rate 25/second burst 50 packets return
                # Excess packets are dropped
                drop
        }

        chain input_lan {
                # Accept port redirections
                ct status dnat accept
                jump accept_from_lan
        }

        chain output_lan {
                jump accept_to_lan
        }

        chain forward_lan {
                # Accept lan to wan forwards
                jump accept_to_wan
                # Accept port forwards
                ct status dnat accept
                jump accept_to_lan
        }

        chain helper_lan {
        }

        chain accept_from_lan {
                iifname $DEV_LAN counter name cnt_lan_in accept
        }

        chain accept_to_lan {
                oifname $DEV_LAN counter name cnt_lan_out accept
        }

        chain input_wan {
                # Allow DHCP Renew
                meta nfproto ipv4 udp dport 68 accept
                # Allow ping
                icmp type echo-request accept
                # Allow IGMP
                meta nfproto ipv4 meta l4proto igmp accept
                # Allow DHCPv6
                meta nfproto ipv6 udp dport 546 accept
                # Allow MLD
                ip6 saddr fe80::/10 icmpv6 type . icmpv6 code { mld-listener-query . no-route, mld-listener-report . no-route, mld-listener-done . no-route, mld2-listener-report . no-route } accept
                # Allow ICMPv6
                icmpv6 type { destination-unreachable, time-exceeded, echo-request, echo-reply, nd-router-solicit, nd-router-advert } limit rate 1000/second accept
                icmpv6 type . icmpv6 code { packet-too-big . no-route, parameter-problem . no-route, parameter-problem . admin-prohibited, nd-neighbor-solicit . no-route, nd-neighbor-advert . no-route } limit rate 1000/second accept
                # Accept port directions
                ct status dnat accept
                jump reject_from_wan
        }

        chain output_wan {
                jump accept_to_wan
        }

        chain forward_wan {
                # Allow ICMPv6 forward
                icmpv6 type { destination-unreachable, time-exceeded, echo-request, echo-reply } limit rate 1000/second accept
                icmpv6 type . icmpv6 code { packet-too-big . no-route, parameter-problem . no-route, parameter-problem . admin-prohibited } limit rate 1000/second accept
                # Allow IPSec-ESP
                meta l4proto esp jump accept_to_lan
                # Allow ISAKMP
                udp dport 500 jump accept_to_lan
                # Accept port forwards
                ct status dnat accept
                jump reject_to_wan
        }

        chain accept_to_wan {
                oifname $DEV_WAN counter name cnt_fwd_wan_out accept
        }

        chain reject_from_wan {
                iifname $DEV_WAN counter name cnt_fwd_wan_in_reject jump handle_reject
        }

        chain reject_to_wan {
                oifname $DEV_WAN counter name cnt_fwd_wan_out_reject jump handle_reject
        }

        chain dstnat {
                type nat hook prerouting priority dstnat; policy accept;
                # Handle lan/wan dstnat traffic
                iifname vmap { $DEV_LAN : jump dstnat_lan, $DEV_WAN : jump dstnat_wan }
        }

        chain srcnat {
                type nat hook postrouting priority srcnat; policy accept;
                # Handle lan/wan srcnat traffic
                oifname vmap { $DEV_LAN : jump srcnat_lan, $DEV_WAN : jump srcnat_wan }
        }

        chain dstnat_lan {
<%              port_forwards.each do |fwd| %>
                ip saddr $NET_PRIVATE ip daddr $PUBLIC_IP tcp dport <%=fwd[:dport]%> dnat ip to <%=fwd[:host]%>:<%=fwd[:port]%> comment "<%=fwd[:rule]%>"
<%              end %> 
        }

        chain srcnat_lan {
<%              port_forwards.each do |fwd| %>
                ip saddr $NET_PRIVATE ip daddr <%=fwd[:host]%> tcp dport <%=fwd[:dport]%> snat ip to $PRIVATE_IP comment "<%=fwd[:rule]%>"
<%              end %>
        }

        chain dstnat_wan {
<%              port_forwards.each do |fwd| %>
                meta nfproto ipv4 tcp dport <%=fwd[:dport]%> counter name cnt_fwd_<%=fwd[:rule]%> dnat ip to <%=fwd[:host]%>:<%=fwd[:port]%> comment "<%=fwd[:rule]%>"
<%              end %>
        }

        chain srcnat_wan {
                # Masquerade IPv4 wan traffic
                meta nfproto ipv4 masquerade
        }

        chain raw_prerouting {
                type filter hook prerouting priority raw; policy accept;
        }

        chain raw_output {
                type filter hook output priority raw; policy accept;
        }

        chain mangle_prerouting {
                type filter hook prerouting priority mangle; policy accept;
        }

        chain mangle_postrouting {
                type filter hook postrouting priority mangle; policy accept;
        }

        chain mangle_input {
                type filter hook input priority mangle; policy accept;
        }

        chain mangle_output {
                type route hook output priority mangle; policy accept;
        }

        chain mangle_forward {
                type filter hook forward priority mangle; policy accept;
                # Fix MTU in wan zone on ingress/egress
                iifname $DEV_WAN tcp flags syn tcp option maxseg size set rt mtu
                oifname $DEV_WAN tcp flags syn tcp option maxseg size set rt mtu
        }
}

EOF
#  puts nft_template.result(binding)
  nft_file = File.open(f, 'w')
  nft_file.print(nft_template.result(binding))
  nft_file.close
end
