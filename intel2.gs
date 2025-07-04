clear_screen // Prepare Screen

//Constants
DEBUG = 1
LOG = 1
ERROR_INVALID_IP = "(intel) ERROR: Invalid IP Address."
WARNING_NO_INTERNET = "(intel) WARNING: No Internet Access."
ERROR_ROUTER_NULL = "(intel) ERROR: Router Not Found."
ERROR_NETSESSION_NULL = "(intel) ERROR: NetSession Object Not Established."
ERROR_PORTS_NULL = "(intel) ERROR: Ports Not Found."
ERROR_LIB_NOT_FOUND = function(lib)
    return "(intel) ERROR: "+lib+" Not Found."
end function

//Simple Boolean Definitions
bool = {0:"False", 1:"True"}
open_close = {0: "Open", 1:"Closed"}
open_close_color = {0: "<color=#00FF00>Open</color>", 1:"<color=#FF0000>Closed</color>"}
bool_color = {0:"<color=red>False</color>", 1:"<color=green>True</color>"}

// Load Metaxploit Library
metaxploit = include_lib("/lib/metaxploit.so")
if not metaxploit then metaxploit = include_lib(current_path+"/metaxploit.so")
if not metaxploit then exit(ERROR_LIB_NOT_FOUND("metaxploit.so"))


// Intel 2.3.2
print("Intel v2.3.2\n")

// Usage: intel2 <ip address>
// Handle Parameters
if params.len != 1 or params[0] == "-h" or params[0] == "--help" then exit("<b>Usage: "+program_path.split("/")[-1]+" [ip_address]</b>")
if not is_valid_ip(params[0]) then exit(ERROR_INVALID_IP) //Validate IP Address
if not get_shell.host_computer.is_network_active then exit(ERROR_INVALID_IP)
ip = params[0]
// Verify LAN Status of IP
isLAN = is_lan_ip(ip)
// Build Router Object
if isLAN then
    router = get_router;
else 
    router = get_router(ip)
end if
if router == null then exit(ERROR_ROUTER_NULL)

// Target IP Address
print("IP: <b>"+ip+"</b>)
print()

// Whois
if not isLAN then 
    print(whois(ip))
else
    print(whois(router.public_ip))
end if
print()

// Kernel Version
version = router.kernel_version
print("Kernel router version: " + version)

// Ports
ports = null
if not isLAN then
   ports = router.used_ports
else
   ports = router.device_ports(ip)
end if
if ports == null then exit(ERROR_PORTS_NULL)
if typeof(ports) == "string" then exit(ports)

// NetSession
net_sesh = metaxploit.net_use(router.public_ip)
if net_sesh == null then exit(ERROR_NETSESSION_NULL)

// Devices Under Gateway
devs_behind_gate = net_sesh.get_num_conn_gateway
print("Devices behind gateway: "+devs_behind_gate)

// LAN IPs
print("\nLAN IPs:")
for dev in router.devices_lan_ip
    print(dev)
end for
print()

// Table Data Organizing and Presentation
info = "LAN PORT <color=#FFFFFF>STATE</color> SERVICE VERSION FWRD USERS/ACTIVE/ROOT"
for port in router.used_ports
    if not port.is_closed then net_sesh = metaxploit.net_use(ip, port.port_number)
    if not net_sesh then exit(ERROR_NETSESSION_NULL)
    fwrd = net_sesh.get_num_portforward
    uar = [net_sesh.get_num_users, net_sesh.is_any_active_user, net_sesh.is_root_active_user]
    if port.is_closed then
        info = info + "\n"+port.get_lan_ip+" "+port.port_number+" "+open_close_color[port.is_closed]+" "+router.port_info(port).split(" ")[0]+" "+router.port_info(port).split(" ")[1]
    else
        net_sesh = metaxploit.net_use(router.public_ip, port.port_number)
        if net_sesh then metalib = net_sesh.dump_lib
        info = info + "\n"+port.get_lan_ip+" "+port.port_number+" "+open_close_color[port.is_closed]+" "+metalib.lib_name+" "+metalib.version+" "+fwrd+" "+uar[0]+"/"+uar[1]+"/"+uar[2]
    end if
end for
print(format_columns(info))

// Firewall Rules
fw_rules = router.firewall_rules
if fw_rules then 
    print("Firewall Rules:")
    print(fw_rules)
end if
// Format Cleanup and Silent Exit
print()
user_input()
