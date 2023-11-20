require 'sinatra'
require 'erb'
require 'dbus'
require 'securerandom'
require "./nftables_rw.rb"
require "./dnsmasq_rw.rb"
require 'ipaddr'

# Use Sinatra sessions, 1h for session expiry, if no SESSION_SECRET is found in the environment, use a random one
enable :sessions
set :sessions, :expire_after => 3600
set :session_secret, ENV.fetch('SESSION_SECRET') { SecureRandom.hex(64) }

bus = DBus::SystemBus.instance
dnsmasqfile = '/etc/dnsmasq.d/mpcrouter-dhcp.conf'
dnsmasqfile = 'mpcrouter-dhcp.conf' if ENV['RACK_ENV'] == 'development'
radvdfile = '/etc/radvd.conf'
radvdfile = 'radvd.conf' if ENV['RACK_ENV'] == 'development'
pwdfile = '/etc/shadow'
pwdfile = 'shadow' if ENV['RACK_ENV'] == 'development'
sysctlfile = '/etc/sysctl.d/01-mpcrouter.conf'
sysctlfile = '01-mpcrouter.conf'  if ENV['RACK_ENV'] == 'development'
nftablesfile = '/etc/nftables.conf'
nftablesfile = 'nftables.conf'  if ENV['RACK_ENV'] == 'development'

def init_nm
  @nm_manager = @nm_service.object("/org/freedesktop/NetworkManager")
  @poi = DBus::ProxyObjectInterface.new(@nm_manager, "org.freedesktop.NetworkManager")
  @poi.define_method("GetDevices", "") # NM 0.7
  @poi.define_method("DeactivateConnection", "in active_connection:o")
  @poi.define_method("ActivateConnection", "in connection:o, in device:o, in specific_object:o, out active_connection:o")
  @devices = @poi.GetDevices
  @nm_settings = @nm_service.object("/org/freedesktop/NetworkManager/Settings")
  @nm_settings_iface = DBus::ProxyObjectInterface.new(@nm_settings, "org.freedesktop.NetworkManager.Settings")
  @nm_settings_iface.define_method("ListConnections", "out connections:ao")
  @nm_settings_iface.define_method("GetConnectionByUuid", "in uuid:s, out connections:o")
  @nm_settings_iface.define_method("AddConnection", "in connection:a{sa{sv}}, out path:o");
  p @nm_settings_iface.ListConnections()
  p @nm_settings_iface
    p @nm_settings_iface["Hostname"]
end

before do
  puts "In before, session:"
  p session

  puts "Path: #{request.path_info}"
  puts "Session authenticated: #{session[:authenticated]}"
  p session.options

  if not (request.path_info.eql? "/login" or request.path_info.eql? "/authenticate") and not session[:authenticated]
    redirect "/login"
  end
end

get '/' do
  @leases ||= []

  begin
    file = File.open("/var/lib/misc/dnsmasq.leases")
  rescue
      puts "Could not open dnsmasq lease file."
  end

  if file then
    file.each_line do |line|
      line_a = line.split(' ')
      lease = { "ts" => line_a[0].to_i - Time.now.to_i,
                "mac" => line_a[1],
                "ip" => line_a[2],
                "host" => line_a[3]
              }
      if lease["ts"] <= 0
        lease["expires"] = "expired"
      else
        l = Time.at(lease["ts"])
        lease["expires"] = sprintf("%d:%02d:%02d", l.hour, l.min, l.sec)
      end
      if lease["ip"]
        @leases.push(lease)
      end
    end
  end
  
  @nm_service = bus.service("org.freedesktop.NetworkManager")
  init_nm
  
  @name = @nm_settings_iface["Hostname"]

  erb :index
end

def aconnection_from_uuid(poi, uuid)
  poi["ActiveConnections"].each do |c_name|
    poi.define_method("DeactivateConnection", "in active_connection:o")
    p c_name
    connection = @nm_service.object(c_name)
    connection_iface = connection["org.freedesktop.NetworkManager.Connection.Active"]
    p connection_iface["Uuid"]
    if uuid == connection_iface["Uuid"] then
      return c_name
    end
  end
end

post '/stop_connection' do
    printf("DONE: %s value %s\n", params[:interface], params[:value])
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    c_name = aconnection_from_uuid(@poi, params[:interface])
    @poi.DeactivateConnection(c_name)
    redirect '/'
end

post '/restart_connection' do
    printf("DONE: %s value %s\n", params[:interface], params[:value])
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    c_name = aconnection_from_uuid(@poi, params[:interface])
    puts "Deactivating #{c_name}"
    p c_name
    @poi.DeactivateConnection(c_name)
    p @nm_settings_iface["Hostname"]
    c_name = @nm_settings_iface.GetConnectionByUuid(params[:interface])
    sleep 1
    setting = @nm_service.object(c_name[0])
    @poi.ActivateConnection(c_name[0], "/", "/")
    sleep 3
    redirect '/'
end

post '/edit_connection' do
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    @name = @nm_settings_iface["Hostname"]
    p "/edit_connection Hostname: " + @name
    begin
      c_name = @nm_settings_iface.GetConnectionByUuid(params[:interface])
    rescue DBus::Error
      redirect '/'
    end
    setting = @nm_service.object(c_name[0])
    @con_setting_if = DBus::ProxyObjectInterface.new(setting, "org.freedesktop.NetworkManager.Settings.Connection")
    @con_setting_if.define_method("GetSettings", "out settings:a{sa{sv}}");
    p @con_setting_if
    p @con_setting_if["Filename"]
    @con_setting_props = @con_setting_if.GetSettings()
    p @con_setting_props
    if @con_setting_props[0]["ipv4"]["method"] == "manual" then
      @currentConMethod4 = "Static IP Address"
    elsif @con_setting_props[0]["ipv4"]["method"] == "auto" then
      @currentConMethod4 = "DHCP"
    end
        
    @con_settings = @con_setting_props[0]
    @currentDevMac = @con_settings["802-3-ethernet"]["mac-address"]
    @currentDev = deviceFromMAC(@currentDevMac)
    @nextStep = nil
    @nextStep = "return" if params[:next].eql? "none"
    p @currentDev
    setEtherdevs()
    erb :editcon
end

def getConnectionByName(name)
  @nm_settings_iface.ListConnections()[0].each do |c|
      c_obj = @nm_service.object(c)
      c_iface = DBus::ProxyObjectInterface.new(c_obj, "org.freedesktop.NetworkManager.Settings.Connection")
      c_iface.define_method("GetSettings", "out a{sa{sv}}:settings");
      c_iface.define_method("Update", "in settings:a{sa{sv}}");
      c_iface.define_method("UpdateUnsaved", "in settings:a{sa{sv}}");
      c_iface.define_method("Update2", "in settings:a{sa{sv}}, in flags:u, in args:a{sv}, out result:a{sv}");
      c_iface.define_method("Delete", "");
      settings = c_iface.GetSettings()
      if name.eql? settings[0]["connection"]["id"] then
          return [ settings, c_iface ]
      end
  end
  [nil, nil]
end

def createDefaultConnection(nm_settings_iface, connection, method)
  puts "createDefaultConnection, method: >#{method}<"
  if "auto".eql? method or method.eql? :auto then # FIXME, see below :auto used, need to be consistent!
      puts "Method: is auto: #{method}"
      new_c = { "connection" => {"id" => connection, "type"=>"802-3-ethernet"}, "ipv4"=>{"method"=>"auto"}}
  elsif "manual".eql? method or method.eql? :manual then
      puts "Method: is manual: #{method}"
      new_c = {
        "connection" => {
          "id" => connection,
          "type" => "802-3-ethernet"
        },
        "ipv4" => {
          "method" => "manual",
          "address-data" => DBus::Data.make_typed("aa{sv}", [{ "address" => "192.168.2.1", "prefix" => 24 }]),
          "addresses" =>  DBus::Data.make_typed("aau", [[16951488, 24, 16885952]]),
#         "gateway" => "192.168.1.3"
        }
      }
  elsif "pppoe".eql? method then
      new_c = {
        "connection" => {
          "id" => connection,
          "type" => "pppoe",
	  "interface-name" => "ppp1"
        },
        "pppoe" => {
          "username" => "user",
          "password" => "passwd",
        }
      }
  end
  p "New connection settings:"
  p new_c
  c_path = nm_settings_iface.AddConnection(new_c)
  c_path
end


def setEtherdevs()
    @etherdevs = []
    @ethermacs = {}
     @devices[0].each do |d_name|
       device = @nm_service.object(d_name)
       device_iface = device["org.freedesktop.NetworkManager.Device"]
       if device_iface["DeviceType"] != 1 then
         next
       end
       d_name = device_iface["Interface"]
       @etherdevs.push(d_name)
       @ethermacs[d_name] = device_iface["HwAddress"]
     end
end

def deviceFromMAC(mac)
  @devices[0].each do |d_name|
    device = @nm_service.object(d_name)
    device_iface = device["org.freedesktop.NetworkManager.Device"]
    if MACtoNumbers(device_iface["HwAddress"]) == mac then
      return device_iface["Interface"]
    end
  end
  return nil
end

def setupDevice(settings)
  @con_settings = settings
  if @con_settings["802-3-ethernet"] then
    @currentDevMac = @con_settings["802-3-ethernet"]["mac-address"]
    p @currentDevMac
    @currentDev = deviceFromMAC(@currentDevMac)
  elsif @con_settings["pppoe"]
    @currentDev = @con_settings["pppoe"]["parent"]
  end
  p @currentDev
  setEtherdevs()
end

get '/setup' do
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    @name = @nm_settings_iface["Hostname"]
    p "/setup Hostname: " + @name
    @name = @nm_settings_iface["Hostname"]
    c_wan, c_iface = getConnectionByName("WAN")
    cwan_path = createDefaultConnection(@nm_settings_iface, "WAN", :auto) if not c_wan

    @con_setting_props, c_iface = getConnectionByName("WAN")

    setupDevice(@con_setting_props[0])
    erb :editcon
end

get '/setupif' do
    interface = params['interface']
    method = params['method']
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    @name = @nm_settings_iface["Hostname"]
    if method
      c, c_iface = getConnectionByName(interface)
      c_iface.Delete() if c
      path = createDefaultConnection(@nm_settings_iface, interface, method)
    end
    c, c_iface = getConnectionByName(interface)
  
    setupDevice(c[0])
    erb :editcon
end


def calculatePrefix(mask)
  IPAddr.new(mask).to_i.to_s(2).count("1")
end

def IPToNumber(address)
  v = 0
  address.split(".").to_a.reverse_each do |i|
    v = 256 * v + i.to_i
  end
  v
end

def NumberToIP(address)
  s = (address & 0xff).to_s(10)
  s = s + "." + ((address & 0xff00) >> 8).to_s
  s = s + "." + ((address & 0xff0000) >> 16).to_s
  s = s + "." + ((address & 0xff000000) >> 24).to_s
  s
end

def MACtoNumbers(mac)
  v = []
  mac.split(":").to_a.each do |i|
    v.push(i.to_i(16))
  end
  v
end
  
def calculateAddresses(ip, mask, gateway)
  [[IPToNumber(ip), 24, IPToNumber(gateway)]]
end

def createVLAN(vid, parent)
  c_new = { "connection" => {"id" => "VLAN#{vid}", "type" => "vlan"} }
  v = {"id" => vid, "parent" => parent}
  ipv4 = {"method" => "disabled"}
  ipv6 = {"method" => "ignore"}
  c_new["ipv4"] = ipv4
  c_new["ipv6"] = ipv6
  c_new["vlan"] = v
  c_path = @nm_settings_iface.AddConnection(c_new)
  c_path
end


post '/setconnection' do
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    setEtherdevs()
    p "IN HERE /setconnection"
    p params
    c, c_iface = getConnectionByName(params[:connection])
    p c
    uuid = c[0]["connection"]["uuid"]

    # A PPPoE connection?
    if not params[:pppuser].empty? then
      c_update = { "connection" => {"id" => params[:connection], "type" => "pppoe", "interface-name"=>"ppp1"},
                   "pppoe" => {
                      "username" => params[:pppuser],
                      "password" => params[:ppppass]
                   }
                 }
      if not params[:vlan].empty? then
        c_update["pppoe"]["parent"] = "#{params[:device]}.#{params[:vlan]}"
      else
        c_update["pppoe"]["parent"] = "#{params[:device]}"
      end
    else
      c_update = { "connection" => {"id" => params[:connection], "type" => "802-3-ethernet", "uuid" => uuid} }
    end

    if params[:ipv4method].eql? "auto" then
      ipv4 = {"method" => "auto"}
      ipv4["dhcp-client-id"] = params[:dhcphostname] if not params[:dhcphostname].empty?
    else
      ipv4 = {"method" => "manual"}
      ipv4["address-data"] = DBus::Data.make_typed("aa{sv}", [{ "address" => params[:ip4address], "prefix" => calculatePrefix(params[:netmask]) }])
      ipv4["addresses"] =  DBus::Data.make_typed("aau", calculateAddresses(params[:ip4address], params[:netmask], params[:gateway]))
      p calculateAddresses(params[:ip4address], params[:netmask], params[:gateway])
    end
    if params[:ipv6address] and not params[:ipv6address].empty? then
      p params[:ipv6address]
    end
    if params[:searchzone] and not params[:searchzone].empty? then
      sz = []
      sz.push(params[:searchzone])
      ipv4["dns-search"] = DBus::Data.make_typed("as", sz)
    end
    dnsdata = []
    dnsdata.push(params[:DNS1]) if not params[:DNS1].empty?
    dnsdata.push(params[:DNS2]) if not params[:DNS2].empty?
    ipv4["dns-data"] = DBus::Data.make_typed("as", dnsdata) if not dnsdata.empty?
    c_update["ipv4"] = ipv4
    p @ethermacs[params[:device]]
    if params[:device].split.size == 1 and params[:pppuser].empty? then
      macarray = MACtoNumbers(@ethermacs[params[:device]])
      p "Macarray:"
      p macarray
      c_update["802-3-ethernet"] = { "mac-address" => DBus::Data.make_typed("ay", macarray) }
      device = deviceFromMAC(@ethermacs[params[:device]])
      p device
    end
    if params[:vlan] and params[:vlan].to_i > 0 then
      vlan_c, vlan_cif = getConnectionByName("VLAN#{params[:vlan].to_i}")
      vlan_cif.Delete() if vlan_cif
      createVLAN(params[:vlan].to_i, params[:device])
    end
    if params[:username] then
        c_update["pppoe"] = {"username" => params[:username], "password" => params[:username]}
    end
    p "Updating to"
    p c_update
    result = c_iface.Update2(DBus::Data.make_typed("a{sa{sv}}", c_update), 0x1, { } )
    p "Updated"
    p result

    if "WAN".eql? params[:connection] and "nextinterface".eql? params[:next] then
      c_lan, c_iface = getConnectionByName("LAN")
      clan_path = createDefaultConnection(@nm_settings_iface, "LAN", :manual) if not c_lan
      redirect "/setupif?interface=LAN"
    elsif params[:next].eql? "none"
      redirect "/"
    else
      redirect "/dhcp?device=#{params[:device]}"
    end
end

def ip_address?(str)
  # We use !! to convert the return value to a boolean
  !!(str =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
end
# ip_address?("192.168.1.1")  # returns true


get '/dhcp' do
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    setEtherdevs()
    
    options = dnsmasq_read(dnsmasqfile)
    # Create a default DHCP address range (x.x.x.50 - x.x.x.150) in the same subnet as the LAN ip address
    c, c_iface = getConnectionByName("VLAN")
    p c
    c, c_iface = getConnectionByName("LAN")
    p options
    if c[0]["ipv4"]["method"] == "manual" then
      @lanaddress = c[0]["ipv4"]["address-data"][0]["address"]
      
      dhcpmin = (IPToNumber(@lanaddress) & 0x00ffffff) + 0x32000000
      dhcpmax = (IPToNumber(@lanaddress) & 0x00ffffff) + 0x96000000
      @dhcpmin = NumberToIP(dhcpmin)
      @dhcpmax = NumberToIP(dhcpmax)
      @dnssearch = c[0]["ipv4"]["dns-search"][0]
      p @dnssearch
    end
    
    c, c_iface = getConnectionByName("WAN")
#    if c[0]["ipv4"]["type"].eql? "802-3-ethernet" and
    @hideDNSSource = "hidden" if not c[0]["ipv4"]["type"].eql? "pppoe"

    interface = deviceFromMAC(@ethermacs[params[:device]])
    puts "1 #{interface}"
    if (not interface) or (interface.empty?) then
    puts "2 #{interface}"
      c_lan, c_liface = getConnectionByName("LAN")
      interface = deviceFromMAC(c_lan[0]["802-3-ethernet"]["mac-address"])
    puts "3 #{interface}"
    end

    # Put LAN interface at beginning of list, so it is the default    
    @etherdevs.delete(interface)
    @etherdevs.insert(0, interface)
    
    erb :editdhcp
end

post '/setdhcp' do
    p params
    puts "OK"
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    setEtherdevs()
    dnsmasq_write(dnsmasqfile, params)
    c, c_iface = getConnectionByName("LAN")

    if not params[:dns6advert].empty? then
      out_file = File.open('/etc/radvd.conf', 'w')

      out_file.print "interface enp2s0 {\n"
      out_file.print "AdvSendAdvert on;\n"
      out_file.print "MinRtrAdvInterval 3;\n"
      out_file.print "MaxRtrAdvInterval 10;\n"
      out_file.print "prefix ::/64 {\n"
      out_file.print "  AdvOnLink on;\n"
      out_file.print "   AdvAutonomous on;\n"
      out_file.print "  AdvRouterAddr on;\n"
      out_file.print "};\n"
      out_file.print " RDNSS #{params[:dns6advert]} {\n"
      out_file.print "      AdvRDNSSPreference 12;\n"
      out_file.print "};\n"
      out_file.close
    end
    
    redirect "/commit_setup" if "commit".eql? params[:next]
    redirect "/"
end

def getIfName(c)
    ifname = ""
    if "pppoe".eql? c[0]["connection"]["type"] then
      ifname = c[0]["connection"]["interface-name"]
      parent = c[0]["pppoe"]["parent"]
      ifname = "#{ifname} using #{parent}"
    else
      ifname = deviceFromMAC(c[0]["802-3-ethernet"]["mac-address"])
    end
    return ifname
end


get '/commit_setup' do
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    @name = @nm_settings_iface["Hostname"]
    c_lan, c_liface = getConnectionByName("LAN")
    c_wan, c_wiface = getConnectionByName("WAN")

    @iflan = getIfName(c_lan)
    @ifwan = getIfName(c_wan)

    erb :commit_setup
end


def wait_active_uuid(poi, uuid, timeout)
  puts "wait_active called, uuid: #{uuid}"
  
  while timeout > 0 do
    connection = nil
    connection_iface = nil
    poi["ActiveConnections"].each do |c_name|
      connection = @nm_service.object(c_name)
      connection_iface = connection["org.freedesktop.NetworkManager.Connection.Active"]
      puts "  Comparing uuid #{connection_iface["Uuid"]}"
      break if uuid == connection_iface["Uuid"]
    end
    puts "Found uuid #{connection_iface["Uuid"]}"
    return nil if uuid != connection_iface["Uuid"]
    sleep 1
    timeout = timeout - 1
    break if connection_iface["State"] == 2
  end

  return nil if timeout < 1

  puts "FOUND connection:"
    p connection_iface["Ip4Config"]
    p connection_iface["Connection"]
    p connection_iface["Id"]
    p connection_iface["Devices"]
    p connection_iface["State"]
    
    return connection_iface
end

get '/setup_complete' do
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    @name = @nm_settings_iface["Hostname"]
    @errors = []
    lan_ip4config_if = nil
    wan_ip4config_if = nil
    
# Start LAN and WAN connections
    begin
      c_lan, c_liface = getConnectionByName("LAN")
      c_name = @nm_settings_iface.GetConnectionByUuid(c_lan[0]["connection"]["uuid"])
      puts "Activating #{c_name[0]}"
      @poi.ActivateConnection(c_name[0], "/", "/")
      @iflan = getIfName(c_lan)
    rescue DBus::Error
      @errors.push("Could not set up LAN connection")
      puts @errors.last
    end
    
    begin
      c_wan, c_wiface = getConnectionByName("WAN")
      c_name = @nm_settings_iface.GetConnectionByUuid(c_wan[0]["connection"]["uuid"])
      puts "Activating #{c_name[0]}"
      @poi.ActivateConnection(c_name[0], "/", "/")
      @ifwan = getIfName(c_wan)
    rescue DBus::Error
      @errors.push "Could not set up WAN connection"
      puts @errors.last
    end

    acon_lan = wait_active_uuid(@poi, c_lan[0]["connection"]["uuid"], 2)
    acon_wan = wait_active_uuid(@poi, c_wan[0]["connection"]["uuid"], 2)

    if acon_lan then
      puts "Active connection lan:"
      lan_ip4config = @nm_service.object(acon_lan["Ip4Config"])
      lan_ip4config_if = lan_ip4config["org.freedesktop.NetworkManager.IP4Config"]
      p lan_ip4config_if["AddressData"]
    else
      @errors.push("Could not activate LAN connection")
      puts @errors.last
    end
    
    if acon_wan then
      puts "Active connection wan:"
      p acon_wan["Ip4Config"]
      p acon_wan["State"]

      wan_ip4config = @nm_service.object(acon_wan["Ip4Config"])
      wan_ip4config_if = wan_ip4config["org.freedesktop.NetworkManager.IP4Config"]
      p wan_ip4config_if
      p wan_ip4config_if["AddressData"]
    else
      @errors.push("Could not activate WAN connection")
      puts @errors.last
    end


# Set up port forwarding
    f = File.open(sysctlfile, 'w')
    f.print "# Enable IPv4 forwarding\n"
    f.print "net.ipv4.ip_forward=1\n"
    f.print "# Enable IPv6 forwarding\n"
    f.print "net.ipv6.conf.all.forwarding=1\n"
    f.close

    begin
      %x|service procps force-reload|
    rescue
      @errors.push "Error resetting sysctl service after writing #{sysctlfile}"
      puts @errors.last
    end

# Set up nftables, using existing port forwards but with updated options
    if wan_ip4config_if and lan_ip4config_if then
      r = nftable_read(nftablesfile)
      port_forwards = r[0]
      options = r[1]
      p port_forwards, options

      options[:landev] = @iflan
      options[:wandev] = @ifwan
      options[:public_ip] = wan_ip4config_if["AddressData"][0]["address"]
      options[:ownip] = lan_ip4config_if["AddressData"][0]["address"]
      prefix = lan_ip4config_if["AddressData"][0]["prefix"]
      options[:lan] = IPAddr.new(options[:ownip]).mask(prefix).to_s + '/' + prefix.to_s
      nftable_write(nftablesfile, port_forwards, options)

      begin
	%x|systemctl enable nftables|
	%x|systemctl restart nftables|
	%x|nft -f #{nftablesfile}|
      rescue
	@errors.push "Error setting up nftables service after writing #{nftablesfile}"
	puts @errors.last
      end

      begin
	%x|systemctl enable dnsmasq.service|
	%x|systemctl restart dnsmasq.service|
      rescue
	@errors.push "Could not start dnsmasq service."
	puts @errors.last
      end
	
      begin
	%x|systemctl enable radvd|
	%x|systemctl restart radvd|
      rescue
	@errors.push "Could not start radvd service."
	puts @errors.last
      end
    end

# Disable Sleep/Hibernation
    if ENV['RACK_ENV'] == 'production' then
      %x|systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target|
    end

# Delete "Wired connection 1" that may have been created automatically by NetworkManager
    if ENV['RACK_ENV'] == 'production' then
      c, c_iface = getConnectionByName("Wired connection 1")
      c_iface.Delete() if c_iface
    end

    @errors.push("None") if @errors.size < 1
    p @errors
    erb :setup_done
end


get '/nftables' do
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    @name = @nm_settings_iface["Hostname"]

    saved_file = nftablesfile + "_saved"
    %x|cp #{nftablesfile} #{saved_file}| if not File.exist?(saved_file)
    
    r = nftable_read(nftablesfile)
    @port_forwards = r[0]
    @options = r[1]
    
    p @port_forwards
    p @options

    if params[:delete] then
      @port_forwards.delete_at(params[:delete].to_i) 
      nftable_write(nftablesfile, @port_forwards, @options)
      p @port_forwards
    end

    c_lan, c_liface = getConnectionByName("LAN")
    c_wan, c_wiface = getConnectionByName("WAN")

    @iflan = getIfName(c_lan)
    @ifwan = getIfName(c_wan)

    erb :editnftables
end

post '/nftablesadd' do
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    @name = @nm_settings_iface["Hostname"]

    r = nftable_read(nftablesfile)
    @port_forwards = r[0]
    @options = r[1]
    p params
    p @port_forwards
    
    new_f = { :rule => params[:rule], :dport => params[:dport], :protocol => params[:protocol], :host => params[:host], :port => params[:port] }
    @port_forwards.push(new_f)
    
    nftable_write(nftablesfile, @port_forwards, @options)
    
    redirect '/nftables'
end

get '/nftablesreset' do
    saved_file = nftablesfile + "_saved"
    %x|mv #{saved_file} #{nftablesfile}|
    redirect '/nftables'
end

get '/nftablessave' do
    saved_file = nftablesfile + "_saved"
    %x|rm #{saved_file}|
    redirect '/'
end

get '/login' do
    @nm_service = bus.service("org.freedesktop.NetworkManager")
    init_nm
    @name = @nm_settings_iface["Hostname"]

    erb :login
end

# TODO: Authentication should be done through D-Bus
post '/authenticate' do
    authenticated = false
    f = File.open(pwdfile, 'r')
    f.each do |line|
      m = line.match /^#{params[:login]}:\$([\w\d]+)\$([\w\d]+)\$([\w\d\.\/]+)\$([\w\d\.\/]+):.*/
      if m then
        r = "#{params[:password]}".crypt("$#{m[1]}$#{m[2]}$#{m[3]}")
        authenticated = true if r.eql? "$#{m[1]}$#{m[2]}$#{m[3]}$#{m[4]}"
        break
      end
    end
    f.close

    session[:authenticated] = authenticated

    if authenticated then
      redirect "/"
    else
      redirect "/login"
    end
end
