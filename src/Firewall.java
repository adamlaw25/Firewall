import java.io.*;
import java.net.InetAddress;
import java.util.*;

public class Firewall {

    // the list of rules defined by the csv file
    HashMap<String, HashMap<Integer, HashSet<String>>> rules;

    public Firewall(String path) throws Exception {
        // initialize the rules list
        rules = new HashMap<>();
        rules.put("inboundtcp", new HashMap<>());
        rules.put("inboundudp", new HashMap<>());
        rules.put("outboundtcp", new HashMap<>());
        rules.put("outboundudp", new HashMap<>());

        setRules(path);
    }

    // method to parse the input csv file to set the rules
    private void setRules(String path) throws Exception {

        File file = new File(path);
        Scanner scanner = new Scanner(file);

        // scan each line of the file which represents a rule
        while (scanner.hasNext()) {
            String rule = scanner.nextLine();
            String[] parts = rule.split(",");

            // the combination of direction and protocol which is the key for the rules map
            String dirPro = parts[0] + parts[1];
            HashMap<Integer, HashSet<String>> portIpRules = rules.get(dirPro);

            String port = parts[2];
            String ip_address = parts[3];

            if (port.contains("-")) { // if the port is a range, then add the ip address rule to all the ports in the range
                String[] portRange = port.split("-");
                int portMin = Integer.parseInt(portRange[0]);
                int portMax = Integer.parseInt(portRange[1]);

                // add a list of acceptable to all the ports in the range
                for (int i = portMin; i <= portMax; i++) {
                    addPortRule(portIpRules, i, ip_address);
                }

            } else { // if the port is just a number
                int portNo = Integer.parseInt(port);
                addPortRule(portIpRules, portNo, ip_address);
            }
        }
    }

    // Method to add ip address rule to a port
    private void addPortRule(HashMap<Integer, HashSet<String>> portIpRules, Integer port, String ip_address) {
        if (portIpRules.containsKey(port)) {
            portIpRules.get(port).add(ip_address);
        } else {
            HashSet<String> ipList = new HashSet<>();
            ipList.add(ip_address);
            portIpRules.put(port, ipList);
        }
    }

    // Method to check if a packet can pass
    public boolean accept_packet(String direction, String protocol, Integer port, String ip_address) throws Exception {
        String dirPro = direction + protocol;
        HashMap<Integer, HashSet<String>> portIpRules = rules.get(dirPro);

        // the long representation of ip address to be checked
        long ipToCheck = ipToLong(InetAddress.getByName(ip_address));

        if (portIpRules.containsKey(port)) {

            for (String ipRule : portIpRules.get(port)) {

                if (ipRule.contains("-")) { // if the ip rule is a range

                    String[] ipRange = ipRule.split("-");
                    String min = ipRange[0];
                    String max = ipRange[1];
                    long minIp = ipToLong(InetAddress.getByName(min));
                    long maxIp = ipToLong(InetAddress.getByName(max));
                    if (ipToCheck >= minIp && ipToCheck <= maxIp) return true;

                } else {

                    long ipRuleAddress = ipToLong(InetAddress.getByName(ipRule));
                    if (ipToCheck == ipRuleAddress) return true;

                }

            }
        }
        return false;
    }

    // Method to convert InetAddress to long attained from StackOverflow: https://stackoverflow.com/questions/11549390/how-does-this-java-code-work-to-convert-an-ip-address
    private static long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result <<= 8;
            result |= octet & 0xff;
        }
        return result;
    }

    public static void main(String[] args) throws Exception{
        Firewall fw = new Firewall("test.csv");
        System.out.println(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"));
        System.out.println(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"));
        System.out.println(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"));
        System.out.println(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"));
        System.out.println(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"));
    }
}
