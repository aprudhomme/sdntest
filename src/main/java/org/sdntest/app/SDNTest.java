/*
 * Copyright 2014-2015 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sdntest.app;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ARP;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ip4Address;
//import org.onlab.packet.MacAddress;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.TCP;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.Permission;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.host.InterfaceIpAddress;
import org.onosproject.net.host.PortAddresses;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.DeviceId;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;

import org.onosproject.net.proxyarp.ProxyArpService;

import java.util.Dictionary;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.ListIterator;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.nio.ByteBuffer;

import static com.google.common.base.Strings.isNullOrEmpty;
import static org.slf4j.LoggerFactory.getLogger;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.onosproject.security.AppGuard.checkPermission;
import static com.google.common.base.Preconditions.checkArgument;
/**
 * Sample reactive forwarding application.
 */
@Component(immediate = true)
public class SDNTest {

    private static final int DEFAULT_TIMEOUT = 0;
    private static final int DEFAULT_PRIORITY = 10;
    private static final String NOT_ARP_REQUEST = "ARP is not a request.";
    private static final String REQUEST_NULL = "ARP or NDP request cannot be null.";

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected EdgePortService edgeService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ProxyArpService proxyArpService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ComponentConfigService cfgService;

    private SDNTPacketProcessor processor = new SDNTPacketProcessor();

    private ApplicationId appId;

    @Property(name = "packetOutOnly", boolValue = false,
            label = "Enable packet-out only forwarding; default is false")
    private boolean packetOutOnly = false;

    @Property(name = "packetOutOfppTable", boolValue = false,
            label = "Enable first packet forwarding using OFPP_TABLE port " +
                    "instead of PacketOut with actual port; default is false")
    private boolean packetOutOfppTable = false;

    @Property(name = "flowTimeout", intValue = DEFAULT_TIMEOUT,
            label = "Configure Flow Timeout for installed flow rules; " +
                    "default is 10 sec")
    private int flowTimeout = DEFAULT_TIMEOUT;

    @Property(name = "flowPriority", intValue = DEFAULT_PRIORITY,
            label = "Configure Flow Priority for installed flow rules; " +
                    "default is 10")
    private int flowPriority = DEFAULT_PRIORITY;

    @Property(name = "ipv6Forwarding", boolValue = false,
            label = "Enable IPv6 forwarding; default is false")
    private boolean ipv6Forwarding = false;

    @Property(name = "matchDstMacOnly", boolValue = false,
            label = "Enable matching Dst Mac Only; default is false")
    private boolean matchDstMacOnly = false;

    @Property(name = "matchVlanId", boolValue = false,
            label = "Enable matching Vlan ID; default is false")
    private boolean matchVlanId = false;

    @Property(name = "matchIpv4Address", boolValue = false,
            label = "Enable matching IPv4 Addresses; default is false")
    private boolean matchIpv4Address = false;

    @Property(name = "matchIpv4Dscp", boolValue = false,
            label = "Enable matching IPv4 DSCP and ECN; default is false")
    private boolean matchIpv4Dscp = false;

    @Property(name = "matchIpv6Address", boolValue = false,
            label = "Enable matching IPv6 Addresses; default is false")
    private boolean matchIpv6Address = false;

    @Property(name = "matchIpv6FlowLabel", boolValue = false,
            label = "Enable matching IPv6 FlowLabel; default is false")
    private boolean matchIpv6FlowLabel = false;

    @Property(name = "matchTcpUdpPorts", boolValue = false,
            label = "Enable matching TCP/UDP ports; default is false")
    private boolean matchTcpUdpPorts = false;

    @Property(name = "matchIcmpFields", boolValue = false,
            label = "Enable matching ICMPv4 and ICMPv6 fields; " +
                    "default is false")
    private boolean matchIcmpFields = false;

    //private Map<String, Map<Short, Short>> vlanMapIn;
    //private Map<String, Map<Short, Short>> vlanMapOut;

    private Map<String, Map<String, Map<Short, Short>>> vlanDstIpMap;
    private Map<String, Map<String, Map<Short, Short>>> vlanTransMacMap;
    private Map<String, Map<String, Map<Short, Short>>> vlanDstMacMap;

    private void initVlanMap() {
        /*vlanMapIn = new HashMap<String, Map<Short, Short>>();
        vlanMapIn.put("00:00:00:00:00:01", new HashMap<Short, Short>());
        vlanMapIn.get("00:00:00:00:00:01").put((short) 10, (short) 7);
        vlanMapIn.put("00:00:00:00:00:02", new HashMap<Short, Short>());
        vlanMapIn.get("00:00:00:00:00:02").put((short) 5, (short) 7);
        vlanMapOut = new HashMap<String, Map<Short, Short>>();
        vlanMapOut.put("00:00:00:00:00:01", new HashMap<Short, Short>());
        vlanMapOut.get("00:00:00:00:00:01").put((short) 7, (short) 10);
        vlanMapOut.put("00:00:00:00:00:02", new HashMap<Short, Short>());
        vlanMapOut.get("00:00:00:00:00:02").put((short) 7, (short) 5);*/

        vlanDstIpMap = new HashMap<String, Map<String, Map<Short, Short>>>();
        vlanDstIpMap.put("00:00:00:00:00:01", new HashMap<String, Map<Short, Short>>());
        vlanDstIpMap.get("00:00:00:00:00:01").put("192.168.1.3", new HashMap<Short, Short>());
        vlanDstIpMap.get("00:00:00:00:00:01").get("192.168.1.3").put((short) 5, (short) 10);

        vlanDstIpMap.put("00:00:00:00:00:02", new HashMap<String, Map<Short, Short>>());
        vlanDstIpMap.get("00:00:00:00:00:02").put("192.168.1.2", new HashMap<Short, Short>());
        vlanDstIpMap.get("00:00:00:00:00:02").get("192.168.1.2").put((short) 10, (short) 5);

        vlanDstMacMap = new HashMap<String, Map<String, Map<Short, Short>>>();
        vlanDstMacMap.put("00:00:00:00:00:01", new HashMap<String, Map<Short, Short>>());
        vlanDstMacMap.get("00:00:00:00:00:01").put("00:00:00:00:00:02", new HashMap<Short, Short>());
        vlanDstMacMap.get("00:00:00:00:00:01").get("00:00:00:00:00:02").put((short) 7, (short) 10);

        vlanDstMacMap.put("00:00:00:00:00:02", new HashMap<String, Map<Short, Short>>());
        vlanDstMacMap.get("00:00:00:00:00:02").put("00:00:00:00:00:01", new HashMap<Short, Short>());
        vlanDstMacMap.get("00:00:00:00:00:02").get("00:00:00:00:00:01").put((short) 7, (short) 5);

        vlanTransMacMap = new HashMap<String, Map<String, Map<Short, Short>>>();
        vlanTransMacMap.put("00:00:00:00:00:01", new HashMap<String, Map<Short, Short>>());
        vlanTransMacMap.get("00:00:00:00:00:01").put("00:00:00:00:00:02", new HashMap<Short, Short>());
        vlanTransMacMap.get("00:00:00:00:00:01").get("00:00:00:00:00:02").put((short) 5, (short) 7);

        vlanTransMacMap.put("00:00:00:00:00:02", new HashMap<String, Map<Short, Short>>());
        vlanTransMacMap.get("00:00:00:00:00:02").put("00:00:00:00:00:01", new HashMap<Short, Short>());
        vlanTransMacMap.get("00:00:00:00:00:02").get("00:00:00:00:00:01").put((short) 10, (short) 7);
    }

    @Activate
    public void activate(ComponentContext context) {
        initVlanMap();
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("org.sdntest.app");

        packetService.addProcessor(processor, PacketProcessor.ADVISOR_MAX + 2);
        readComponentConfiguration(context);
        requestIntercepts();
        addDefaultRules();

        log.info("Started with Application ID {}", appId.id());
    }

    @Deactivate
    public void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        removeDefaultRules();
        withdrawIntercepts();
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        readComponentConfiguration(context);
        requestIntercepts();
    }

    /**
     * Request packet in via PacketService.
     */
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        //selector.matchEthType(Ethernet.TYPE_VLAN);
        //packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     * Request packet in via PacketService.
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        //selector.matchEthType(Ethernet.TYPE_VLAN);
        //packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    // init known rules as needed
    private void addDefaultRules() {
        return;
    }

    private void removeDefaultRules() {
        return;
    }

    /**
     * Extracts properties from the component configuration context.
     *
     * @param context the component context
     */
    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();
        boolean packetOutOnlyEnabled =
                isPropertyEnabled(properties, "packetOutOnly");
        if (packetOutOnly != packetOutOnlyEnabled) {
            packetOutOnly = packetOutOnlyEnabled;
            log.info("Configured. Packet-out only forwarding is {}",
                     packetOutOnly ? "enabled" : "disabled");
        }
        boolean packetOutOfppTableEnabled =
                isPropertyEnabled(properties, "packetOutOfppTable");
        if (packetOutOfppTable != packetOutOfppTableEnabled) {
            packetOutOfppTable = packetOutOfppTableEnabled;
            log.info("Configured. Forwarding using OFPP_TABLE port is {}",
                     packetOutOfppTable ? "enabled" : "disabled");
        }
        boolean ipv6ForwardingEnabled =
                isPropertyEnabled(properties, "ipv6Forwarding");
        if (ipv6Forwarding != ipv6ForwardingEnabled) {
            ipv6Forwarding = ipv6ForwardingEnabled;
            log.info("Configured. IPv6 forwarding is {}",
                     ipv6Forwarding ? "enabled" : "disabled");
        }
        boolean matchDstMacOnlyEnabled =
                isPropertyEnabled(properties, "matchDstMacOnly");
        if (matchDstMacOnly != matchDstMacOnlyEnabled) {
            matchDstMacOnly = matchDstMacOnlyEnabled;
            log.info("Configured. Match Dst MAC Only is {}",
                     matchDstMacOnly ? "enabled" : "disabled");
        }
        boolean matchVlanIdEnabled =
                isPropertyEnabled(properties, "matchVlanId");
        if (matchVlanId != matchVlanIdEnabled) {
            matchVlanId = matchVlanIdEnabled;
            log.info("Configured. Matching Vlan ID is {}",
                     matchVlanId ? "enabled" : "disabled");
        }
        boolean matchIpv4AddressEnabled =
                isPropertyEnabled(properties, "matchIpv4Address");
        if (matchIpv4Address != matchIpv4AddressEnabled) {
            matchIpv4Address = matchIpv4AddressEnabled;
            log.info("Configured. Matching IPv4 Addresses is {}",
                     matchIpv4Address ? "enabled" : "disabled");
        }
        boolean matchIpv4DscpEnabled =
                isPropertyEnabled(properties, "matchIpv4Dscp");
        if (matchIpv4Dscp != matchIpv4DscpEnabled) {
            matchIpv4Dscp = matchIpv4DscpEnabled;
            log.info("Configured. Matching IPv4 DSCP and ECN is {}",
                     matchIpv4Dscp ? "enabled" : "disabled");
        }
        boolean matchIpv6AddressEnabled =
                isPropertyEnabled(properties, "matchIpv6Address");
        if (matchIpv6Address != matchIpv6AddressEnabled) {
            matchIpv6Address = matchIpv6AddressEnabled;
            log.info("Configured. Matching IPv6 Addresses is {}",
                     matchIpv6Address ? "enabled" : "disabled");
        }
        boolean matchIpv6FlowLabelEnabled =
                isPropertyEnabled(properties, "matchIpv6FlowLabel");
        if (matchIpv6FlowLabel != matchIpv6FlowLabelEnabled) {
            matchIpv6FlowLabel = matchIpv6FlowLabelEnabled;
            log.info("Configured. Matching IPv6 FlowLabel is {}",
                     matchIpv6FlowLabel ? "enabled" : "disabled");
        }
        boolean matchTcpUdpPortsEnabled =
                isPropertyEnabled(properties, "matchTcpUdpPorts");
        if (matchTcpUdpPorts != matchTcpUdpPortsEnabled) {
            matchTcpUdpPorts = matchTcpUdpPortsEnabled;
            log.info("Configured. Matching TCP/UDP fields is {}",
                     matchTcpUdpPorts ? "enabled" : "disabled");
        }
        boolean matchIcmpFieldsEnabled =
                isPropertyEnabled(properties, "matchIcmpFields");
        if (matchIcmpFields != matchIcmpFieldsEnabled) {
            matchIcmpFields = matchIcmpFieldsEnabled;
            log.info("Configured. Matching ICMP (v4 and v6) fields is {}",
                     matchIcmpFields ? "enabled" : "disabled");
        }
        Integer flowTimeoutConfigured =
                getIntegerProperty(properties, "flowTimeout");
        if (flowTimeoutConfigured == null) {
            log.info("Flow Timeout is not configured, default value is {}",
                     flowTimeout);
        } else {
            flowTimeout = flowTimeoutConfigured;
            log.info("Configured. Flow Timeout is configured to {}",
                     flowTimeout, " seconds");
        }
        Integer flowPriorityConfigured =
                getIntegerProperty(properties, "flowPriority");
        if (flowPriorityConfigured == null) {
            log.info("Flow Priority is not configured, default value is {}",
                     flowPriority);
        } else {
            flowPriority = flowPriorityConfigured;
            log.info("Configured. Flow Priority is configured to {}",
                     flowPriority);
        }
    }

    /**
     * Get Integer property from the propertyName
     * Return null if propertyName is not found.
     *
     * @param properties   properties to be looked up
     * @param propertyName the name of the property to look up
     * @return value when the propertyName is defined or return null
     */
    private static Integer getIntegerProperty(Dictionary<?, ?> properties,
                                              String propertyName) {
        Integer value = null;
        try {
            String s = (String) properties.get(propertyName);
            value = isNullOrEmpty(s) ? value : Integer.parseInt(s.trim());
        } catch (NumberFormatException | ClassCastException e) {
            value = null;
        }
        return value;
    }

    /**
     * Check property name is defined and set to true.
     *
     * @param properties   properties to be looked up
     * @param propertyName the name of the property to look up
     * @return true when the propertyName is defined and set to true
     */
    private static boolean isPropertyEnabled(Dictionary<?, ?> properties,
                                             String propertyName) {
        boolean enabled = false;
        try {
            String flag = (String) properties.get(propertyName);
            if (flag != null) {
                enabled = flag.trim().equals("true");
            }
        } catch (ClassCastException e) {
            // No propertyName defined.
            enabled = false;
        }
        return enabled;
    }

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class SDNTPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            //log.info("Got packet");
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            //if (context.isHandled()) {
                //return;
            //}
            //log.info("not handled");

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }
            //log.info("eth packet");

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                return;
            }
            //log.info("not control");

            HostId id = HostId.hostId(ethPkt.getDestinationMAC());
            HostId sid = HostId.hostId(ethPkt.getSourceMAC());

            // Do not process link-local addresses in any way.
            if (id.mac().isLinkLocal()) {
                return;
            }

            log.info("not local smac: {}, dmac: {}, type: {}",
                    ethPkt.getSourceMAC(), ethPkt.getDestinationMAC(), ethPkt.getEtherType());
            log.info("vlan: {}, loc: {}.", ethPkt.getVlanID(), context.inPacket().receivedFrom());
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                handleArp(context, ethPkt);
                return;
            } else {
                log.info("Not arp.");
            }

            Boolean mapVlans = false;
            Short inVlan = ethPkt.getVlanID();
            Short transVlan = ethPkt.getVlanID();
            Short outVlan = ethPkt.getVlanID();

            if (vlanTransMacMap.containsKey(ethPkt.getSourceMAC().toString())) {
                if (vlanTransMacMap.get(ethPkt.getSourceMAC().toString())
                        .containsKey(ethPkt.getDestinationMAC().toString())) {
                    if (vlanTransMacMap.get(ethPkt.getSourceMAC().toString())
                            .get(ethPkt.getDestinationMAC().toString())
                            .containsKey(ethPkt.getVlanID())) {
                        inVlan = ethPkt.getVlanID();
                        transVlan = vlanTransMacMap.get(ethPkt.getSourceMAC().toString())
                                .get(ethPkt.getDestinationMAC().toString()).get(ethPkt.getVlanID());
                        if (vlanDstMacMap.containsKey(ethPkt.getSourceMAC().toString())) {
                            if (vlanDstMacMap.get(ethPkt.getSourceMAC().toString())
                                    .containsKey(ethPkt.getDestinationMAC().toString())) {
                                if (vlanDstMacMap.get(ethPkt.getSourceMAC().toString())
                                    .get(ethPkt.getDestinationMAC().toString())
                                    .containsKey(transVlan)) {
                                        outVlan = vlanDstMacMap.get(ethPkt.getSourceMAC().toString())
                                                .get(ethPkt.getDestinationMAC().toString()).get(transVlan);
                                        mapVlans = true;
                                }
                            }
                        }
                    }
                }
            }

            sid = HostId.hostId(ethPkt.getSourceMAC(), VlanId.vlanId(inVlan));

            if (mapVlans) {
                id = HostId.hostId(ethPkt.getDestinationMAC(), VlanId.vlanId(outVlan));
            } else {
                id = HostId.hostId(ethPkt.getDestinationMAC(), VlanId.vlanId(inVlan));
            }

            log.info("Hids: {}, Hidd: {}.", sid, id);

            Host dst = hostService.getHost(id);
            Host src = hostService.getHost(sid);

            log.info("Hs: {}, Hd: {}.", src, dst);

            // Do we know who this is for? If not, flood and bail.
            if (dst == null) {
                // fix for vlan
                log.info("flood dev: {}", pkt.receivedFrom().deviceId());
                flood(context);
                return;
            }

            //log.info("hosts found");

            // Otherwise, get a set of paths that lead from here to the
            // destination edge switch.
            Set<Path> paths =
                    topologyService.getPaths(topologyService.currentTopology(),
                                             src.location().deviceId(),
                                             dst.location().deviceId());
            if (paths.isEmpty()) {
                // If there are no paths, flood and bail.
                flood(context);
                return;
            }

            Path path = (Path) paths.toArray()[0];

            // Otherwise, pick a path that does not lead back to where we
            // came from; if no such path, flood and bail.
            //Path path = pickForwardPath(paths, pkt.receivedFrom().port());
            //if (path == null) {
            //    log.warn("Doh... don't know where to go... {} -> {} received on {}",
            //             ethPkt.getSourceMAC(), ethPkt.getDestinationMAC(),
            //             pkt.receivedFrom());
            //    flood(context);
            //    return;
            //}

            // Otherwise forward and be done with it.
            installRules(context, path, mapVlans, inVlan, transVlan, outVlan);
        }

    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    // Indicated whether this is an IPv6 multicast packet.
    private boolean isIpv6Multicast(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV6 && eth.isMulticast();
    }

    // Selects a path from the given set that does not lead back to the
    // specified port.
    private Path pickForwardPath(Set<Path> paths, PortNumber notToPort) {
        for (Path path : paths) {
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return null;
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                                             context.inPacket().receivedFrom())) {
            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void installRules(PacketContext context, Path path, Boolean mapVlans,
            Short inVlan, Short transVlan, Short outVlan) {

        log.info("Installing rules.");

        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        HostId sid = HostId.hostId(ethPkt.getSourceMAC(), VlanId.vlanId(inVlan));
        HostId id;
        if (mapVlans) {
            id = HostId.hostId(ethPkt.getDestinationMAC(), VlanId.vlanId(outVlan));
        } else {
            id = HostId.hostId(ethPkt.getDestinationMAC(), VlanId.vlanId(inVlan));
        }
        Host dst = hostService.getHost(id);
        Host src = hostService.getHost(sid);

        installRule(context, dst.location().port(), dst.location().deviceId(), mapVlans, transVlan, outVlan);
        for (ListIterator<Link> it = path.links().listIterator(path.links().size()); it.hasPrevious();) {
            Link link = it.previous();
            if (link.src().deviceId().equals(src.location().deviceId())) {
                installRule(context, link.src().port(), link.src().deviceId(), mapVlans, inVlan, transVlan);
            } else {
                installRule(context, link.src().port(), link.src().deviceId(), mapVlans, transVlan, transVlan);
            }
        }

        if (ethPkt.getEtherType() != Ethernet.TYPE_ARP) {
            packetOut(context, PortNumber.TABLE);
        }
    }

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber, DeviceId device, Boolean mapVlan,
            Short vlanIn, Short vlanOut) {
        log.info("install rule: device: {}, port: {}, map: {}, vIn: {}, vout: {}", device, portNumber,
                mapVlan, vlanIn, vlanOut);
        //
        // We don't support (yet) buffer IDs in the Flow Service so
        // packet out first.
        //
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        // If ARP packet than forward directly to output port
        if (inPkt.getEtherType() == Ethernet.TYPE_ARP) {
            if (context.inPacket().receivedFrom().deviceId().equals(device)) {
                packetOut(context, portNumber);
            }
            return;
        }

        //
        // If matchDstMacOnly
        //    Create flows matching dstMac only
        // Else
        //    Create flows with default matching and include configured fields
        //
        if (matchDstMacOnly) {
            selectorBuilder.matchEthDst(inPkt.getDestinationMAC());
        } else {
            selectorBuilder.matchEthSrc(inPkt.getSourceMAC())
                    .matchEthDst(inPkt.getDestinationMAC());

            // If configured Match Vlan ID
            if (mapVlan) {
                selectorBuilder.matchVlanId(VlanId.vlanId(vlanIn));
            }

            //
            // If configured and EtherType is IPv4 - Match IPv4 and
            // TCP/UDP/ICMP fields
            //
            if (matchIpv4Address && inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
                byte ipv4Protocol = ipv4Packet.getProtocol();
                Ip4Prefix matchIp4SrcPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                                          Ip4Prefix.MAX_MASK_LENGTH);
                Ip4Prefix matchIp4DstPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                                          Ip4Prefix.MAX_MASK_LENGTH);
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                        .matchIPSrc(matchIp4SrcPrefix)
                        .matchIPDst(matchIp4DstPrefix);

                if (matchIpv4Dscp) {
                    byte dscp = ipv4Packet.getDscp();
                    byte ecn = ipv4Packet.getEcn();
                    selectorBuilder.matchIPDscp(dscp).matchIPEcn(ecn);
                }

                if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchTcpSrc(tcpPacket.getSourcePort())
                            .matchTcpDst(tcpPacket.getDestinationPort());
                }
                if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchUdpSrc(udpPacket.getSourcePort())
                            .matchUdpDst(udpPacket.getDestinationPort());
                }
                if (matchIcmpFields && ipv4Protocol == IPv4.PROTOCOL_ICMP) {
                    ICMP icmpPacket = (ICMP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchIcmpType(icmpPacket.getIcmpType())
                            .matchIcmpCode(icmpPacket.getIcmpCode());
                }
            }

            //
            // If configured and EtherType is IPv6 - Match IPv6 and
            // TCP/UDP/ICMP fields
            //
            if (matchIpv6Address && inPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Packet = (IPv6) inPkt.getPayload();
                byte ipv6NextHeader = ipv6Packet.getNextHeader();
                Ip6Prefix matchIp6SrcPrefix =
                        Ip6Prefix.valueOf(ipv6Packet.getSourceAddress(),
                                          Ip6Prefix.MAX_MASK_LENGTH);
                Ip6Prefix matchIp6DstPrefix =
                        Ip6Prefix.valueOf(ipv6Packet.getDestinationAddress(),
                                          Ip6Prefix.MAX_MASK_LENGTH);
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV6)
                        .matchIPv6Src(matchIp6SrcPrefix)
                        .matchIPv6Dst(matchIp6DstPrefix);

                if (matchIpv6FlowLabel) {
                    selectorBuilder.matchIPv6FlowLabel(ipv6Packet.getFlowLabel());
                }

                if (matchTcpUdpPorts && ipv6NextHeader == IPv6.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchTcpSrc(tcpPacket.getSourcePort())
                            .matchTcpDst(tcpPacket.getDestinationPort());
                }
                if (matchTcpUdpPorts && ipv6NextHeader == IPv6.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchUdpSrc(udpPacket.getSourcePort())
                            .matchUdpDst(udpPacket.getDestinationPort());
                }
                if (matchIcmpFields && ipv6NextHeader == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchIcmpv6Type(icmp6Packet.getIcmpType())
                            .matchIcmpv6Code(icmp6Packet.getIcmpCode());
                }
            }
        }
        TrafficTreatment treatment;
        if (mapVlan && !vlanIn.equals(vlanOut)) {
            treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .setVlanId(VlanId.vlanId(vlanOut))
                .build();
        } else {
            treatment = DefaultTrafficTreatment.builder()
                    .setOutput(portNumber)
                    .build();
        }

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                //.makeTemporary(flowTimeout)
                .add();

        flowObjectiveService.forward(device,
                                     forwardingObjective);

        //
        // If packetOutOfppTable
        //  Send packet back to the OpenFlow pipeline to match installed flow
        // Else
        //  Send packet direction on the appropriate port
        //
        //if (packetOutOfppTable) {
        //    packetOut(context, PortNumber.TABLE);
        //} else {
        //    packetOut(context, portNumber);
        //}
    }

    private boolean handleArp(PacketContext context, Ethernet ethPkt) {
        ARP arp = (ARP) ethPkt.getPayload();
        //log.info("Doing arp.");

        short dstVlan = ethPkt.getVlanID();
        //log.info("MACsrc: {}.", ethPkt.getSourceMAC().toString());
        if (vlanDstIpMap.containsKey(ethPkt.getSourceMAC().toString())) {
            //log.info("Src MAC found");
            Ip4Address targetAddress = Ip4Address.valueOf(arp.getTargetProtocolAddress());
            if (vlanDstIpMap.get(ethPkt.getSourceMAC().toString())
                    .containsKey(targetAddress.toString())) {
                //log.info("Dst Ip found");
                if (vlanDstIpMap.get(ethPkt.getSourceMAC().toString())
                    .get(targetAddress.toString())
                    .containsKey(dstVlan)) {
                    dstVlan = vlanDstIpMap.get(ethPkt.getSourceMAC().toString())
                            .get(targetAddress.toString())
                            .get(dstVlan);
                    //log.info("New dst vlan: {}.", dstVlan);
                }
            }
        }
        ethPkt.setVlanID(dstVlan);

        if (arp.getOpCode() == ARP.OP_REPLY) {
            log.info("Arp reply.");
            forward(ethPkt, context.inPacket().receivedFrom());
        } else if (arp.getOpCode() == ARP.OP_REQUEST) {
            log.info("Arp request.");
            replyArp(ethPkt, context.inPacket().receivedFrom());
        } else {
            log.info("Unknown Arp op.");
            return false;
        }
        context.block();
        return true;
    }

    private void forward(Ethernet eth, ConnectPoint inPort) {
        checkPermission(Permission.PACKET_WRITE);

        checkNotNull(eth, REQUEST_NULL);

        Host h = hostService.getHost(HostId.hostId(eth.getDestinationMAC(),
                VlanId.vlanId(eth.getVlanID())));

        if (h == null) {
            flood(eth, inPort);
        } else {
            TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
            builder.setOutput(h.location().port());
            packetService.emit(new DefaultOutboundPacket(h.location().deviceId(),
                    builder.build(), ByteBuffer.wrap(eth.serialize())));
        }

    }

    private void replyArp(Ethernet eth, ConnectPoint inPort) {
        ARP arp = (ARP) eth.getPayload();
        checkArgument(arp.getOpCode() == ARP.OP_REQUEST, NOT_ARP_REQUEST);
        checkNotNull(inPort);
        Ip4Address targetAddress = Ip4Address.valueOf(arp.getTargetProtocolAddress());

        VlanId vlan = VlanId.vlanId(eth.getVlanID());

        if (isOutsidePort(inPort)) {
            // If the request came from outside the network, only reply if it was
            // for one of our external addresses.
            Set<PortAddresses> addressSet =
                    hostService.getAddressBindingsForPort(inPort);

            for (PortAddresses addresses : addressSet) {
                for (InterfaceIpAddress ia : addresses.ipAddresses()) {
                    if (ia.ipAddress().equals(targetAddress)) {
                        Ethernet arpReply =
                                ARP.buildArpReply(targetAddress, addresses.mac(), eth);
                        sendTo(arpReply, inPort);
                    }
                }
            }
            return;
        }

        // See if we have the target host in the host store

        Set<Host> hosts = hostService.getHostsByIp(targetAddress);

        Host dst = null;
        Host src = hostService.getHost(HostId.hostId(eth.getSourceMAC(),
                VlanId.vlanId(eth.getVlanID())));

        for (Host host : hosts) {
            if (host.vlan().equals(vlan)) {
                dst = host;
                break;
            }
        }

        if (src != null && dst != null) {
            //log.info("Arp dst known.");
            // We know the target host so we can respond
            Ethernet arpReply = ARP.buildArpReply(targetAddress, dst.mac(), eth);
            sendTo(arpReply, inPort);
            return;
        }
        //log.info("Arp dst not known.");

        // If the source address matches one of our external addresses
        // it could be a request from an internal host to an external
        // address. Forward it over to the correct port.
        Ip4Address source =
                Ip4Address.valueOf(arp.getSenderProtocolAddress());
        Set<PortAddresses> sourceAddresses = findPortsInSubnet(source);
        boolean matched = false;
        for (PortAddresses pa : sourceAddresses) {
            for (InterfaceIpAddress ia : pa.ipAddresses()) {
                if (ia.ipAddress().equals(source) &&
                        pa.vlan().equals(vlan)) {
                    matched = true;
                    sendTo(eth, pa.connectPoint());
                    break;
                }
            }
        }

        if (matched) {
            return;
        }

        //
        // The request couldn't be resolved.
        // Flood the request on all ports except the incoming port.
        //
        flood(eth, inPort);
        return;
    }

    private boolean isOutsidePort(ConnectPoint port) {
        //
        // TODO: Is this sufficient to identify outside-facing ports: just
        // having IP addresses on a port?
        //
        return !hostService.getAddressBindingsForPort(port).isEmpty();
    }

    private void sendTo(Ethernet packet, ConnectPoint outPort) {
        if (!edgeService.isEdgePoint(outPort)) {
            // Sanity check to make sure we don't send the packet out an
            // internal port and create a loop (could happen due to
            // misconfiguration).
            return;
        }

        TrafficTreatment.Builder builder = DefaultTrafficTreatment.builder();
        builder.setOutput(outPort.port());
        packetService.emit(new DefaultOutboundPacket(outPort.deviceId(),
                builder.build(), ByteBuffer.wrap(packet.serialize())));
    }

    private Set<PortAddresses> findPortsInSubnet(IpAddress target) {
        Set<PortAddresses> result = new HashSet<>();
        for (PortAddresses addresses : hostService.getAddressBindings()) {
            result.addAll(addresses.ipAddresses().stream().filter(ia -> ia.subnetAddress().contains(target)).
                    map(ia -> addresses).collect(Collectors.toList()));
        }
        return result;
    }

    private void flood(Ethernet request, ConnectPoint inPort) {
        log.info("Flood edge ports, vlan: {}.", request.getVlanID());
        TrafficTreatment.Builder builder = null;
        ByteBuffer buf = ByteBuffer.wrap(request.serialize());

        for (ConnectPoint connectPoint : edgeService.getEdgePoints()) {
            if (isOutsidePort(connectPoint) || connectPoint.equals(inPort)) {
                continue;
            }

            log.info("Send connect point: {}.", connectPoint);
            builder = DefaultTrafficTreatment.builder();
            builder.setOutput(connectPoint.port());
            packetService.emit(new DefaultOutboundPacket(connectPoint.deviceId(),
                    builder.build(), buf));
        }

    }
}