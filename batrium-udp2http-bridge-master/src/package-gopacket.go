import (
  _ "github.com/google/gopacket/layers"
)

// Decode a packet
packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)
// Get the TCP layer from this packet
if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
  fmt.Println("This is a TCP packet!")
  // Get actual TCP data from this layer
  tcp, _ := tcpLayer.(*layers.TCP)
  fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
}
// Iterate over all layers, printing out each layer type
for _, layer := range packet.Layers() {
  fmt.Println("PACKET LAYER:", layer.LayerType())
}

// Decode an ethernet packet

ethP := gopacket.NewPacket(p1, layers.LayerTypeEthernet, gopacket.Default)

// Decode an IPv6 header and everything it contains

ipP := gopacket.NewPacket(p2, layers.LayerTypeIPv6, gopacket.Default)

// Decode a TCP header and its payload

tcpP := gopacket.NewPacket(p3, layers.LayerTypeTCP, gopacket.Default)

packetSource := http_artificial_profile.pcap  // construct using pcap or pfring
for packet := range packetSource.Packets() {
  handlePacket(packet)  // do something with each packet
}
// Create a packet, but don't actually decode anything yet

packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Lazy)

// Now, decode the packet up to the first IPv4 layer found but no further.
// If no IPv4 layer was found, the whole packet will be decoded looking for
// it.

ip4 := packet.Layer(layers.LayerTypeIPv4)

// Decode all layers and return them.  The layers up to the first IPv4 layer
// are already decoded, and will not require decoding a second time.

layers := packet.Layers()

// This channel returns new byte slices, each of which points to a new
// memory location that's guaranteed immutable for the duration of the
// packet.

for data := range myByteSliceChannel {
  p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
  doSomethingWithPacket(p)
}

// Get packets from some source
for packet := range someSource {
  if app := packet.ApplicationLayer(); app != nil {
    if strings.Contains(string(app.Payload()), "magic string") {
      fmt.Println("Found magic string in a packet!")
    }
  }
}

packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)
if err := packet.ErrorLayer(); err != nil {
  fmt.Println("Error decoding some part of the packet:", err)
}

packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Lazy)
netFlow := packet.NetworkLayer().NetworkFlow()
src, dst := netFlow.Endpoints()
reverseFlow := gopacket.NewFlow(dst, src)

flows := map[gopacket.Endpoint]chan gopacket.Packet
packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Lazy)
// Send all TCP packets to channels based on their destination port.
if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
  flows[tcp.TransportFlow().Dst()] <- packet
}
// Look for all packets with the same source and destination network address
if net := packet.NetworkLayer(); net != nil {
  src, dst := net.NetworkFlow().Endpoints()
  if src == dst {
    fmt.Println("Fishy packet has same network source and dst: %s", src)
  }
}

// Find all packets coming from UDP port 1000 to UDP port 500
interestingFlow := gopacket.FlowFromEndpoints(layers.NewUDPPortEndpoint(1000), layers.NewUDPPortEndpoint(500))
if t := packet.NetworkLayer(); t != nil && t.TransportFlow() == interestingFlow {
  fmt.Println("Found that UDP flow I was looking for!")
}

channels := [8]chan gopacket.Packet
for i := 0; i < 8; i++ {
  channels[i] = make(chan gopacket.Packet)
  go packetHandler(channels[i])
}
for packet := range getPackets() {
  if net := packet.NetworkLayer(); net != nil {
    channels[int(net.NetworkFlow().FastHash()) & 0x7] <- packet
  }
}

// Create a layer type, should be unique and high, so it doesn't conflict,
// giving it a name and a decoder to use.
var MyLayerType = gopacket.RegisterLayerType(12345, gopacket.LayerTypeMetadata{Name: "MyLayerType", Decoder: gopacket.DecodeFunc(decodeMyLayer)})

// Implement my layer
type MyLayer struct {
  StrangeHeader []byte
  payload []byte
}
func (m MyLayer) LayerType() gopacket.LayerType { return MyLayerType }
func (m MyLayer) LayerContents() []byte { return m.StrangeHeader }
func (m MyLayer) LayerPayload() []byte { return m.payload }

// Now implement a decoder... this one strips off the first 4 bytes of the
// packet.
func decodeMyLayer(data []byte, p gopacket.PacketBuilder) error {
  // Create my layer
  p.AddLayer(&MyLayer{data[:4], data[4:]})
  // Determine how to handle the rest of the packet
  return p.NextDecoder(layers.LayerTypeEthernet)
}

// Finally, decode your packets:
p := gopacket.NewPacket(data, MyLayerType, gopacket.Lazy)

func main() {
  var eth layers.Ethernet
  var ip4 layers.IPv4
  var ip6 layers.IPv6
  var tcp layers.TCP
  parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
  decoded := []gopacket.LayerType{}
  for packetData := range somehowGetPacketData() {
    if err := parser.DecodeLayers(packetData, &decoded); err != nil {
      fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
      continue
    }
    for _, layerType := range decoded {
      switch layerType {
        case layers.LayerTypeIPv6:
          fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
        case layers.LayerTypeIPv4:
          fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
      }
    }
  }
}

packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)
if err := packet.ErrorLayer(); err != nil {
  fmt.Println("Error decoding some part of the packet:", err)
}

packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Lazy)
netFlow := packet.NetworkLayer().NetworkFlow()
src, dst := netFlow.Endpoints()
reverseFlow := gopacket.NewFlow(dst, src)

flows := map[gopacket.Endpoint]chan gopacket.Packet
packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Lazy)
// Send all TCP packets to channels based on their destination port.
if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
  flows[tcp.TransportFlow().Dst()] <- packet
}
// Look for all packets with the same source and destination network address
if net := packet.NetworkLayer(); net != nil {
  src, dst := net.NetworkFlow().Endpoints()
  if src == dst {
    fmt.Println("Fishy packet has same network source and dst: %s", src)
  }
}
// Find all packets coming from UDP port 1000 to UDP port 500
interestingFlow := gopacket.FlowFromEndpoints(layers.NewUDPPortEndpoint(1000), layers.NewUDPPortEndpoint(500))
if t := packet.NetworkLayer(); t != nil && t.TransportFlow() == interestingFlow {
  fmt.Println("Found that UDP flow I was looking for!")
}

channels := [8]chan gopacket.Packet
for i := 0; i < 8; i++ {
  channels[i] = make(chan gopacket.Packet)
  go packetHandler(channels[i])
}
for packet := range getPackets() {
  if net := packet.NetworkLayer(); net != nil {
    channels[int(net.NetworkFlow().FastHash()) & 0x7] <- packet
  }
}

// Create a layer type, should be unique and high, so it doesn't conflict,
// giving it a name and a decoder to use.
var MyLayerType = gopacket.RegisterLayerType(12345, gopacket.LayerTypeMetadata{Name: "MyLayerType", Decoder: gopacket.DecodeFunc(decodeMyLayer)})

// Implement my layer
type MyLayer struct {
  StrangeHeader []byte
  payload []byte
}
func (m MyLayer) LayerType() gopacket.LayerType { return MyLayerType }
func (m MyLayer) LayerContents() []byte { return m.StrangeHeader }
func (m MyLayer) LayerPayload() []byte { return m.payload }

// Now implement a decoder... this one strips off the first 4 bytes of the
// packet.
func decodeMyLayer(data []byte, p gopacket.PacketBuilder) error {
  // Create my layer
  p.AddLayer(&MyLayer{data[:4], data[4:]})
  // Determine how to handle the rest of the packet
  return p.NextDecoder(layers.LayerTypeEthernet)
}

// Finally, decode your packets:
p := gopacket.NewPacket(data, MyLayerType, gopacket.Lazy)


func main() {
  var eth layers.Ethernet
  var ip4 layers.IPv4
  var ip6 layers.IPv6
  var tcp layers.TCP
  parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
  decoded := []gopacket.LayerType{}
  for packetData := range somehowGetPacketData() {
    if err := parser.DecodeLayers(packetData, &decoded); err != nil {
      fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
      continue
    }
    for _, layerType := range decoded {
      switch layerType {
        case layers.LayerTypeIPv6:
          fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
        case layers.LayerTypeIPv4:
          fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
      }
    }
  }
}

dlp := gopacket.NewDecodingLayerParser(LayerTypeEthernet)
dlp.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
var eth layers.Ethernet
dlp.AddDecodingLayer(&eth)
// ... add layers and use DecodingLayerParser as usual...

func main() {
  var eth layers.Ethernet
  var ip4 layers.IPv4
  var ip6 layers.IPv6
  var tcp layers.TCP
  dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil))
  dlc = dlc.Put(&eth)
  dlc = dlc.Put(&ip4)
  dlc = dlc.Put(&ip6)
  dlc = dlc.Put(&tcp)
  // you may specify some meaningful DecodeFeedback
  decoder := dlc.LayersDecoder(LayerTypeEthernet, gopacket.NilDecodeFeedback)
  decoded := make([]gopacket.LayerType, 0, 20)
  for packetData := range somehowGetPacketData() {
    lt, err := decoder(packetData, &decoded)
    if err != nil {
      fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
      continue
    }
    if lt != gopacket.LayerTypeZero {
      fmt.Fprintf(os.Stderr, "unknown layer type: %v\n", lt)
      continue
    }
    for _, layerType := range decoded {
      // examine decoded layertypes just as already shown above
    }
  }
}

ip := &layers.IPv4{
  SrcIP: net.IP{1, 2, 3, 4},
  DstIP: net.IP{5, 6, 7, 8},
  // etc...
}
buf := gopacket.NewSerializeBuffer()
opts := gopacket.SerializeOptions{}  // See SerializeOptions for more details.
err := ip.SerializeTo(buf, opts)
if err != nil { panic(err) }
fmt.Println(buf.Bytes())  // prints out a byte slice containing the serialized IPv4 layer.

buf := gopacket.NewSerializeBuffer()
opts := gopacket.SerializeOptions{}
gopacket.SerializeLayers(buf, opts,
  &layers.Ethernet{},
  &layers.IPv4{},
  &layers.TCP{},
  gopacket.Payload([]byte{1, 2, 3, 4}))
packetData := buf.Bytes()

