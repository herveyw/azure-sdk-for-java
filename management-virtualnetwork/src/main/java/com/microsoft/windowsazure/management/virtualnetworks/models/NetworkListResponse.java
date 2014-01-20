/**
 * 
 * Copyright (c) Microsoft and contributors.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

// Warning: This code was generated by a tool.
// 
// Changes to this file may cause incorrect behavior and will be lost if the
// code is regenerated.

package com.microsoft.windowsazure.management.virtualnetworks.models;

import com.microsoft.windowsazure.core.OperationResponse;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Iterator;

/**
* The response structure for the Server List operation.
*/
public class NetworkListResponse extends OperationResponse implements Iterable<NetworkListResponse.VirtualNetworkSite>
{
    private ArrayList<NetworkListResponse.VirtualNetworkSite> virtualNetworkSites;
    
    /**
    * @return The VirtualNetworkSites value.
    */
    public ArrayList<NetworkListResponse.VirtualNetworkSite> getVirtualNetworkSites()
    {
        return this.virtualNetworkSites;
    }
    
    /**
    * @param virtualNetworkSitesValue The VirtualNetworkSites value.
    */
    public void setVirtualNetworkSites(final ArrayList<NetworkListResponse.VirtualNetworkSite> virtualNetworkSitesValue)
    {
        this.virtualNetworkSites = virtualNetworkSitesValue;
    }
    
    /**
    * Initializes a new instance of the NetworkListResponse class.
    *
    */
    public NetworkListResponse()
    {
        super();
        this.virtualNetworkSites = new ArrayList<NetworkListResponse.VirtualNetworkSite>();
    }
    
    /**
    * Gets the sequence of VirtualNetworkSites.
    *
    */
    public Iterator<NetworkListResponse.VirtualNetworkSite> iterator()
    {
        return this.getVirtualNetworkSites().iterator();
    }
    
    public static class AddressSpace
    {
        private ArrayList<String> addressPrefixes;
        
        /**
        * Address spaces, in CIDR format in the virtual network
        * @return The AddressPrefixes value.
        */
        public ArrayList<String> getAddressPrefixes()
        {
            return this.addressPrefixes;
        }
        
        /**
        * Address spaces, in CIDR format in the virtual network
        * @param addressPrefixesValue The AddressPrefixes value.
        */
        public void setAddressPrefixes(final ArrayList<String> addressPrefixesValue)
        {
            this.addressPrefixes = addressPrefixesValue;
        }
        
        /**
        * Initializes a new instance of the AddressSpace class.
        *
        */
        public AddressSpace()
        {
            this.addressPrefixes = new ArrayList<String>();
        }
    }
    
    /**
    * Specifies the type of connection of the local network site. The value of
    * this element can be either IPsec or Dedicated. The default value is
    * IPsec.
    */
    public static class Connection
    {
        private LocalNetworkConnectionType type;
        
        /**
        * @return The Type value.
        */
        public LocalNetworkConnectionType getType()
        {
            return this.type;
        }
        
        /**
        * @param typeValue The Type value.
        */
        public void setType(final LocalNetworkConnectionType typeValue)
        {
            this.type = typeValue;
        }
    }
    
    public static class DnsServer
    {
        private InetAddress address;
        
        /**
        * The IPv4 address of the DNS server.
        * @return The Address value.
        */
        public InetAddress getAddress()
        {
            return this.address;
        }
        
        /**
        * The IPv4 address of the DNS server.
        * @param addressValue The Address value.
        */
        public void setAddress(final InetAddress addressValue)
        {
            this.address = addressValue;
        }
        
        private String name;
        
        /**
        * The name of the DNS server.
        * @return The Name value.
        */
        public String getName()
        {
            return this.name;
        }
        
        /**
        * The name of the DNS server.
        * @param nameValue The Name value.
        */
        public void setName(final String nameValue)
        {
            this.name = nameValue;
        }
    }
    
    /**
    * Contains gateway references to the local network sites that the virtual
    * network can connect to.
    */
    public static class Gateway
    {
        private GatewayProfile profile;
        
        /**
        * The gateway connection size.
        * @return The Profile value.
        */
        public GatewayProfile getProfile()
        {
            return this.profile;
        }
        
        /**
        * The gateway connection size.
        * @param profileValue The Profile value.
        */
        public void setProfile(final GatewayProfile profileValue)
        {
            this.profile = profileValue;
        }
        
        private ArrayList<NetworkListResponse.LocalNetworkSite> sites;
        
        /**
        * The list of local network sites that the virtual network can connect
        * to.
        * @return The Sites value.
        */
        public ArrayList<NetworkListResponse.LocalNetworkSite> getSites()
        {
            return this.sites;
        }
        
        /**
        * The list of local network sites that the virtual network can connect
        * to.
        * @param sitesValue The Sites value.
        */
        public void setSites(final ArrayList<NetworkListResponse.LocalNetworkSite> sitesValue)
        {
            this.sites = sitesValue;
        }
        
        private NetworkListResponse.VPNClientAddressPool vPNClientAddressPool;
        
        /**
        * The VPNClientAddressPool reserves a pool of IP addresses for VPN
        * clients. This object is used for point-to-site connectivity.
        * @return The VPNClientAddressPool value.
        */
        public NetworkListResponse.VPNClientAddressPool getVPNClientAddressPool()
        {
            return this.vPNClientAddressPool;
        }
        
        /**
        * The VPNClientAddressPool reserves a pool of IP addresses for VPN
        * clients. This object is used for point-to-site connectivity.
        * @param vPNClientAddressPoolValue The VPNClientAddressPool value.
        */
        public void setVPNClientAddressPool(final NetworkListResponse.VPNClientAddressPool vPNClientAddressPoolValue)
        {
            this.vPNClientAddressPool = vPNClientAddressPoolValue;
        }
        
        /**
        * Initializes a new instance of the Gateway class.
        *
        */
        public Gateway()
        {
            this.sites = new ArrayList<NetworkListResponse.LocalNetworkSite>();
        }
    }
    
    /**
    * Contains the list of parameters defining the local network site.
    */
    public static class LocalNetworkSite
    {
        private NetworkListResponse.AddressSpace addressSpace;
        
        /**
        * The address space of the local network site.
        * @return The AddressSpace value.
        */
        public NetworkListResponse.AddressSpace getAddressSpace()
        {
            return this.addressSpace;
        }
        
        /**
        * The address space of the local network site.
        * @param addressSpaceValue The AddressSpace value.
        */
        public void setAddressSpace(final NetworkListResponse.AddressSpace addressSpaceValue)
        {
            this.addressSpace = addressSpaceValue;
        }
        
        private ArrayList<NetworkListResponse.Connection> connections;
        
        /**
        * Specifies the types of connections to the local network site.
        * @return The Connections value.
        */
        public ArrayList<NetworkListResponse.Connection> getConnections()
        {
            return this.connections;
        }
        
        /**
        * Specifies the types of connections to the local network site.
        * @param connectionsValue The Connections value.
        */
        public void setConnections(final ArrayList<NetworkListResponse.Connection> connectionsValue)
        {
            this.connections = connectionsValue;
        }
        
        private String name;
        
        /**
        * The name of the local network site.
        * @return The Name value.
        */
        public String getName()
        {
            return this.name;
        }
        
        /**
        * The name of the local network site.
        * @param nameValue The Name value.
        */
        public void setName(final String nameValue)
        {
            this.name = nameValue;
        }
        
        private InetAddress vpnGatewayAddress;
        
        /**
        * The IPv4 address of the local network site.
        * @return The VpnGatewayAddress value.
        */
        public InetAddress getVpnGatewayAddress()
        {
            return this.vpnGatewayAddress;
        }
        
        /**
        * The IPv4 address of the local network site.
        * @param vpnGatewayAddressValue The VpnGatewayAddress value.
        */
        public void setVpnGatewayAddress(final InetAddress vpnGatewayAddressValue)
        {
            this.vpnGatewayAddress = vpnGatewayAddressValue;
        }
        
        /**
        * Initializes a new instance of the LocalNetworkSite class.
        *
        */
        public LocalNetworkSite()
        {
            this.connections = new ArrayList<NetworkListResponse.Connection>();
        }
    }
    
    public static class Subnet
    {
        private String addressPrefix;
        
        /**
        * Represents an address space, in CIDR format that defines the subnet
        * @return The AddressPrefix value.
        */
        public String getAddressPrefix()
        {
            return this.addressPrefix;
        }
        
        /**
        * Represents an address space, in CIDR format that defines the subnet
        * @param addressPrefixValue The AddressPrefix value.
        */
        public void setAddressPrefix(final String addressPrefixValue)
        {
            this.addressPrefix = addressPrefixValue;
        }
        
        private String name;
        
        /**
        * Name for the subnet.
        * @return The Name value.
        */
        public String getName()
        {
            return this.name;
        }
        
        /**
        * Name for the subnet.
        * @param nameValue The Name value.
        */
        public void setName(final String nameValue)
        {
            this.name = nameValue;
        }
    }
    
    /**
    * Contains the collections of parameters used to configure a virtual
    * network space that is dedicated to your subscription without overlapping
    * with other networks
    */
    public static class VirtualNetworkSite
    {
        private NetworkListResponse.AddressSpace addressSpace;
        
        /**
        * The list of network address spaces for a virtual network site. This
        * represents the overall network space contained within the virtual
        * network site.
        * @return The AddressSpace value.
        */
        public NetworkListResponse.AddressSpace getAddressSpace()
        {
            return this.addressSpace;
        }
        
        /**
        * The list of network address spaces for a virtual network site. This
        * represents the overall network space contained within the virtual
        * network site.
        * @param addressSpaceValue The AddressSpace value.
        */
        public void setAddressSpace(final NetworkListResponse.AddressSpace addressSpaceValue)
        {
            this.addressSpace = addressSpaceValue;
        }
        
        private String affinityGroup;
        
        /**
        * An affinity group, which indirectly refers to the location where the
        * virtual network exists.
        * @return The AffinityGroup value.
        */
        public String getAffinityGroup()
        {
            return this.affinityGroup;
        }
        
        /**
        * An affinity group, which indirectly refers to the location where the
        * virtual network exists.
        * @param affinityGroupValue The AffinityGroup value.
        */
        public void setAffinityGroup(final String affinityGroupValue)
        {
            this.affinityGroup = affinityGroupValue;
        }
        
        private ArrayList<NetworkListResponse.DnsServer> dnsServers;
        
        /**
        * The list of on DNS Servers associated with the virtual network site.
        * @return The DnsServers value.
        */
        public ArrayList<NetworkListResponse.DnsServer> getDnsServers()
        {
            return this.dnsServers;
        }
        
        /**
        * The list of on DNS Servers associated with the virtual network site.
        * @param dnsServersValue The DnsServers value.
        */
        public void setDnsServers(final ArrayList<NetworkListResponse.DnsServer> dnsServersValue)
        {
            this.dnsServers = dnsServersValue;
        }
        
        private NetworkListResponse.Gateway gateway;
        
        /**
        * Gateway that contains a list of Local Network Sites which enables the
        * Virtual network site to communicate with a customer’s on premise
        * networks.
        * @return The Gateway value.
        */
        public NetworkListResponse.Gateway getGateway()
        {
            return this.gateway;
        }
        
        /**
        * Gateway that contains a list of Local Network Sites which enables the
        * Virtual network site to communicate with a customer’s on premise
        * networks.
        * @param gatewayValue The Gateway value.
        */
        public void setGateway(final NetworkListResponse.Gateway gatewayValue)
        {
            this.gateway = gatewayValue;
        }
        
        private String id;
        
        /**
        * A unique string identifier that represents the virtual network site.
        * @return The Id value.
        */
        public String getId()
        {
            return this.id;
        }
        
        /**
        * A unique string identifier that represents the virtual network site.
        * @param idValue The Id value.
        */
        public void setId(final String idValue)
        {
            this.id = idValue;
        }
        
        private String label;
        
        /**
        * The friendly identifier of the site.
        * @return The Label value.
        */
        public String getLabel()
        {
            return this.label;
        }
        
        /**
        * The friendly identifier of the site.
        * @param labelValue The Label value.
        */
        public void setLabel(final String labelValue)
        {
            this.label = labelValue;
        }
        
        private String name;
        
        /**
        * Name of the virtual network site.
        * @return The Name value.
        */
        public String getName()
        {
            return this.name;
        }
        
        /**
        * Name of the virtual network site.
        * @param nameValue The Name value.
        */
        public void setName(final String nameValue)
        {
            this.name = nameValue;
        }
        
        private String state;
        
        /**
        * Current status of the virtual network. (Created, Creating, Updating,
        * Deleting, Unavailable)
        * @return The State value.
        */
        public String getState()
        {
            return this.state;
        }
        
        /**
        * Current status of the virtual network. (Created, Creating, Updating,
        * Deleting, Unavailable)
        * @param stateValue The State value.
        */
        public void setState(final String stateValue)
        {
            this.state = stateValue;
        }
        
        private ArrayList<NetworkListResponse.Subnet> subnets;
        
        /**
        * The list of network subnets for a virtual network site. All network
        * subnets must be contained within the overall virtual network address
        * spaces.
        * @return The Subnets value.
        */
        public ArrayList<NetworkListResponse.Subnet> getSubnets()
        {
            return this.subnets;
        }
        
        /**
        * The list of network subnets for a virtual network site. All network
        * subnets must be contained within the overall virtual network address
        * spaces.
        * @param subnetsValue The Subnets value.
        */
        public void setSubnets(final ArrayList<NetworkListResponse.Subnet> subnetsValue)
        {
            this.subnets = subnetsValue;
        }
        
        /**
        * Initializes a new instance of the VirtualNetworkSite class.
        *
        */
        public VirtualNetworkSite()
        {
            this.dnsServers = new ArrayList<NetworkListResponse.DnsServer>();
            this.subnets = new ArrayList<NetworkListResponse.Subnet>();
        }
    }
    
    /**
    * The VPNClientAddressPool reserves a pool of IP addresses for VPN clients.
    * This object is used for point-to-site connectivity.
    */
    public static class VPNClientAddressPool
    {
        private ArrayList<String> addressPrefixes;
        
        /**
        * The CIDR identifiers that identify addresses in the pool.
        * @return The AddressPrefixes value.
        */
        public ArrayList<String> getAddressPrefixes()
        {
            return this.addressPrefixes;
        }
        
        /**
        * The CIDR identifiers that identify addresses in the pool.
        * @param addressPrefixesValue The AddressPrefixes value.
        */
        public void setAddressPrefixes(final ArrayList<String> addressPrefixesValue)
        {
            this.addressPrefixes = addressPrefixesValue;
        }
        
        /**
        * Initializes a new instance of the VPNClientAddressPool class.
        *
        */
        public VPNClientAddressPool()
        {
            this.addressPrefixes = new ArrayList<String>();
        }
    }
}
