/*
 * E_RoutingAssignment.cpp
 *
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

#include "RoutingAssignment.hpp"

namespace E {

RoutingAssignment::RoutingAssignment(Host &host)
    : HostModule("UDP", host), RoutingInfoInterface(host),
      TimerModule("UDP", host) {}

RoutingAssignment::~RoutingAssignment() {}

void RoutingAssignment::initialize() {

  for (int port = 0; port < 16; ++port) {
    std::optional<ipv4_t> ipOpt = getIPAddr(port);
    if (!ipOpt.has_value()) continue;

    ipv4_t ipv4 = ipOpt.value();

    Packet packet(66);

    ipv4_t broadcast = {255, 255, 255, 255};
    uint32_t ip32;

    packet.writeData(26, &ipv4, 4);
    packet.writeData(30, &broadcast, 4);
    packet.readData(26, &ip32, 4);

    // 2. 자기 자신을 routingTable에 등록 (metric 0, nextHop 자기 자신)
    routingTable[ip32] = RouteEntry{ip32, 0, port};
    myInterfaces.push_back({ip32, port});

    // 3. RIP Request 패킷 생성


    // UDP Header 구성
    uint16_t srcPort = htons(520);
    uint16_t dstPort = htons(520);
    uint16_t udpLength = htons(8 + 4 + 20); // UDP header (8) + RIP header (4) + 1 entry (20)

    packet.writeData(34, &srcPort, 2);
    packet.writeData(36, &dstPort, 2);
    packet.writeData(38, &udpLength, 2);

    // RIP Header (command=1, version=1, 2 bytes zero)
    rip_header_t ripheader;
    ripheader.command = 1;
    ripheader.version = 1;
    ripheader.zero_0 = 0;

    packet.writeData(42, &ripheader, 4);

    // RIP Entry (Address Family=0, IP=0, metric=16)
    rip_entry_t ripentry;
    ripentry.address_family = htons(0);
    ripentry.zero_1 = 0;
    ripentry.zero_2 = 0;
    ripentry.zero_3 = 0;
    ripentry.metric = htonl(16);

    packet.writeData(46, &ripentry, 20);

    sendPacket("IPv4", std::move(packet));
  }


}

void RoutingAssignment::finalize() {}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {
  // Implement below

  Packet packet(66);
  uint32_t ip32;

  packet.writeData(26, &ipv4, 4);
  packet.readData(26, &ip32, 4);

  auto it = routingTable.find(ip32);
  if (it != routingTable.end()) {
    return it->second.metric;
  }

  return -1;
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {

  uint16_t srcport, destport;
  uint32_t srcIP;
  ipv4_t srcip;
  bool updated = false;

  rip_header_t ripheader;
  rip_entry_t ripentry;

  packet.readData(34, &srcport, 2); 
  packet.readData(36, &destport, 2); 
  packet.readData(26, &srcIP, 4);
  packet.readData(26, &srcip, 4);
  packet.readData(42, &ripheader, 4);

  if(ripheader.command==1){

    Packet response(46+20*routingTable.size());

    response.writeData(30, &srcIP, 4);

    int recvPort = getRoutingTable(srcip);
    std::optional<ipv4_t> ipOpt = getIPAddr(recvPort);
    ipv4_t ipv4 = ipOpt.value();
    uint16_t udpLength = htons(8 + 4 + 20*routingTable.size());

    response.writeData(26, &ipv4, 4);
    response.writeData(34, &destport, 4);
    response.writeData(36, &srcport, 2); 
    response.writeData(38, &udpLength, 2);

    rip_header_t response_header;
    rip_entry_t response_entry;

    response_header.command = 2;
    response_header.version = 1;
    response_header.zero_0 = 0;

    response.writeData(42, &response_header, 4);   

    size_t offset = 46;

    for (const auto& entry : routingTable) {
      uint32_t destIP = entry.first;
      const RouteEntry& route = entry.second;

      response_entry.address_family = htons(2);
      response_entry.metric = route.metric;
      response_entry.ip_addr = destIP;

      response.writeData(offset, &response_entry, 20);
      offset += 20;
    }

    sendPacket(fromModule, std::move(response));
  }
  else if(ripheader.command==2){
    size_t offset = 46;
    while (offset + 20 <= packet.getSize()) {
      packet.readData(46, &ripentry, 20);
      uint32_t metric = ntohl(ripentry.metric);
      if (metric > 15) metric = 16;
      Size newCost = std::min((Size)metric + 1, (Size)16);

      auto it = routingTable.find(ripentry.ip_addr);
      if (it == routingTable.end() || it->second.metric > newCost) {
        int recvPort = getRoutingTable(srcip);
        routingTable[ripentry.ip_addr] = RouteEntry{srcIP, newCost, recvPort};
        updated = true;
      }
      offset += 20;
    }
  }

  if (updated) {
      // 예: 다음 timerCallback에서 반영되도록 깃발 세우기
    }
}

void RoutingAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
